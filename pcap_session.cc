#include <node_buffer.h>
#include <node_version.h>
#include <assert.h>
#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <cstring>
#include <string.h>

#include "pcap_session.h"

using namespace v8;

Persistent<Function> PcapSession::constructor;

PcapSession::PcapSession() {};
PcapSession::~PcapSession() {};

void PcapSession::Init(Handle<Object> exports) {
  Isolate* isolate = Isolate::GetCurrent();
  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
  tpl->SetClassName(String::NewSymbol("PcapSession"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  // Prototype
  tpl->PrototypeTemplate()->Set(String::NewSymbol("open_live"),
      FunctionTemplate::New(OpenLive)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("open_offline"),
      FunctionTemplate::New(OpenOffline)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("dispatch"),
      FunctionTemplate::New(Dispatch)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("fileno"),
      FunctionTemplate::New(Fileno)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("close"),
      FunctionTemplate::New(Close)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("stats"),
      FunctionTemplate::New(Stats)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("inject"),
      FunctionTemplate::New(Inject)->GetFunction());

  constructor.Reset(isolate, tpl->GetFunction());
  exports->Set(String::NewSymbol("PcapSession"), tpl->GetFunction());
}

void PcapSession::New(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

  PcapSession* obj = new PcapSession();
  obj->Wrap(args.This());

  args.GetReturnValue().Set(args.This());
}

// PacketReady is called from within pcap, still on the stack of Dispatch.  It should be called
// only one time per Dispatch, but sometimes it gets called 0 times.  PacketReady invokes the
// JS callback associated with the dispatch() call in JS.
//
// Stack:
// 1. readWatcher.callback (pcap.js)
// 2. session.dispatch (pcap.js)
// 3. Dispatch (pcap_session.cc)
// 4. pcap_dispatch (libpcap)
// 5. PacketReady (pcap_session.cc)
// 6. session.dispatch callback (pcap.js)
//
void PcapSession::PacketReady(u_char *s, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    PcapSession* session = (PcapSession *)s;

    if (session->pcap_dump_handle != NULL) {
        pcap_dump((u_char *) session->pcap_dump_handle, pkthdr, packet);
    }

    size_t copy_len = pkthdr->caplen;
    if (copy_len > session->buffer_length) {
        copy_len = session->buffer_length;
    }
    memcpy(session->buffer_data, packet, copy_len);

    TryCatch try_catch;

    Local<Object> packet_header = Object::New();

    packet_header->Set(String::New("tv_sec"), Integer::NewFromUnsigned(pkthdr->ts.tv_sec));
    packet_header->Set(String::New("tv_usec"), Integer::NewFromUnsigned(pkthdr->ts.tv_usec));
    packet_header->Set(String::New("caplen"), Integer::NewFromUnsigned(pkthdr->caplen));
    packet_header->Set(String::New("len"), Integer::NewFromUnsigned(pkthdr->len));

    Local<Value> argv[1] = { packet_header };

    v8::Local<v8::Function> callback = v8::Local<v8::Function>::New(isolate, session->packet_ready_cb);
    callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);

    if (try_catch.HasCaught())  {
        node::FatalException(try_catch);
    }
}

void PcapSession::Dispatch(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    if (args.Length() != 1) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Dispatch takes exactly one arguments")));
      return;
    }

    if (!node::Buffer::HasInstance(args[0])) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "First argument must be a buffer")));
      return;
    }

    PcapSession* session = ObjectWrap::Unwrap<PcapSession>(args.This());

#if NODE_VERSION_AT_LEAST(0,3,0)
    Local<Object> buffer_obj = args[0]->ToObject();
    session->buffer_data = node::Buffer::Data(buffer_obj);
    session->buffer_length = node::Buffer::Length(buffer_obj);
#else
    node::Buffer *buffer_obj = ObjectWrap::Unwrap<node::Buffer>(args[0]->ToObject());
    session->buffer_data = buffer_obj->data();
    session->buffer_length = buffer_obj->length();
#endif

    int packet_count;
    do {
        packet_count = pcap_dispatch(session->pcap_handle, 1, PacketReady, (u_char *)session);
    } while (packet_count > 0);

    args.GetReturnValue().Set(Integer::NewFromUnsigned(packet_count));
}

void PcapSession::Open(bool live, const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);
    char errbuf[PCAP_ERRBUF_SIZE];

    if (args.Length() == 5 || args.Length() == 6) {
        if (!args[0]->IsString()) {
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "pcap Open: args[0] must be a String")));
          return;
        }
        if (!args[1]->IsString()) {
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "pcap Open: args[1] must be a String")));
          return;
        }
        if (!args[2]->IsInt32()) {
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "pcap Open: args[2] must be a Number")));
          return;
        }
        if (!args[3]->IsString()) {
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "pcap Open: args[3] must be a String")));
          return;
        }
        if (!args[4]->IsFunction()) {
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "pcap Open: args[4] must be a Function")));
          return;
        }
        if (args.Length() == 6) {
            if (!args[5]->IsBoolean()) {
                isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "pcap Open: args[5] must be a Boolean")));
              return;
            }
        }
    } else {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "pcap Open: expecting 4 arguments")));
      return;
    }
    String::Utf8Value device(args[0]->ToString());
    String::Utf8Value filter(args[1]->ToString());
    int buffer_size = args[2]->Int32Value();
    String::Utf8Value pcap_output_filename(args[3]->ToString());

    PcapSession* session = ObjectWrap::Unwrap<PcapSession>(args.This());

    session->packet_ready_cb.Reset(isolate, Handle<Function>::Cast(args[4]));
    session->pcap_dump_handle = NULL;

    if (live) {
        if (pcap_lookupnet((char *) *device, &session->net, &session->mask, errbuf) == -1) {
            session->net = 0;
            session->mask = 0;
            fprintf(stderr, "warning: %s - this may not actually work\n", errbuf);
        }

        session->pcap_handle = pcap_create((char *) *device, errbuf);
        if (session->pcap_handle == NULL) {
            isolate->ThrowException(Exception::Error(String::New(errbuf)));
          return;
        }

        // 64KB is the max IPv4 packet size
        if (pcap_set_snaplen(session->pcap_handle, 65535) != 0) {
            isolate->ThrowException(Exception::Error(String::New("error setting snaplen")));
          return;
        }

        // always use promiscuous mode
        if (pcap_set_promisc(session->pcap_handle, 1) != 0) {
            isolate->ThrowException(Exception::Error(String::New("error setting promiscuous mode")));
          return;
        }

        // Try to set buffer size.  Sometimes the OS has a lower limit that it will silently enforce.
        if (pcap_set_buffer_size(session->pcap_handle, buffer_size) != 0) {
            isolate->ThrowException(Exception::Error(String::New("error setting buffer size")));
          return;
        }

        // set "timeout" on read, even though we are also setting nonblock below.  On Linux this is required.
        if (pcap_set_timeout(session->pcap_handle, 1000) != 0) {
            isolate->ThrowException(Exception::Error(String::New("error setting read timeout")));
          return;
        }

        // fixes a previous to-do that was here.
        if (args.Length() == 6) {
            if (args[5]->Int32Value()) {
                if (pcap_set_rfmon(session->pcap_handle, 1) != 0) {
                    isolate->ThrowException(Exception::Error(String::New(pcap_geterr(session->pcap_handle))));
                  return;
                }
            }
        }

        if (pcap_activate(session->pcap_handle) != 0) {
           isolate->ThrowException(Exception::Error(String::New(pcap_geterr(session->pcap_handle))));
          return;
        }

        if (strlen((char *) *pcap_output_filename) > 0) {
            session->pcap_dump_handle = pcap_dump_open(session->pcap_handle, (char *) *pcap_output_filename);
            if (session->pcap_dump_handle == NULL) {
                isolate->ThrowException(Exception::Error(String::New("error opening dump")));
              return;
            }
        }

        if (pcap_setnonblock(session->pcap_handle, 1, errbuf) == -1) {
          isolate->ThrowException(Exception::Error(String::New(errbuf)));
          return;
        }
    } else {
        // Device is the path to the savefile
        session->pcap_handle = pcap_open_offline((char *) *device, errbuf);
        if (session->pcap_handle == NULL) {
            isolate->ThrowException(Exception::Error(String::New(errbuf)));
          return;
        }
    }

    if (filter.length() != 0) {
      if (pcap_compile(session->pcap_handle, &session->fp, (char *) *filter, 1, session->net) == -1) {
        isolate->ThrowException(Exception::Error(String::New(pcap_geterr(session->pcap_handle))));
        return;
      }

      if (pcap_setfilter(session->pcap_handle, &session->fp) == -1) {
        isolate->ThrowException(Exception::Error(String::New(pcap_geterr(session->pcap_handle))));
        return;
      }
      pcap_freecode(&session->fp);
    }

    // Work around buffering bug in BPF on OSX 10.6 as of May 19, 2010
    // This may result in dropped packets under load because it disables the (broken) buffer
    // http://seclists.org/tcpdump/2010/q1/110
#if defined(__APPLE_CC__) || defined(__APPLE__)
    #include <net/bpf.h>
    int fd = pcap_get_selectable_fd(session->pcap_handle);
    int v = 1;
    ioctl(fd, BIOCIMMEDIATE, &v);
    // TODO - check return value
#endif

    int link_type = pcap_datalink(session->pcap_handle);

    Local<Value> ret;
    switch (link_type) {
    case DLT_NULL:
        ret = String::New("LINKTYPE_NULL");
        break;
    case DLT_EN10MB: // most wifi interfaces pretend to be "ethernet"
        ret =  String::New("LINKTYPE_ETHERNET");
        break;
    case DLT_IEEE802_11_RADIO: // 802.11 "monitor mode"
        ret = String::New("LINKTYPE_IEEE802_11_RADIO");
        break;
    case DLT_RAW: // "raw IP"
        ret = String::New("LINKTYPE_RAW");
        break;
    case DLT_LINUX_SLL: // "Linux cooked capture"
        ret = String::New("LINKTYPE_LINUX_SLL");
        break;
    default:
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unknown linktype %d", link_type);
        ret = String::New(errbuf);
        break;
    }
    args.GetReturnValue().Set(ret);
}

void PcapSession::OpenLive(const FunctionCallbackInfo<Value>& args)
{
    Open(true, args);
}

void PcapSession::OpenOffline(const FunctionCallbackInfo<Value>& args)
{
    Open(false, args);
}

void PcapSession::Close(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    PcapSession* session = ObjectWrap::Unwrap<PcapSession>(args.This());

    if (session->pcap_dump_handle != NULL) {
        pcap_dump_close(session->pcap_dump_handle);
        session->pcap_dump_handle = NULL;
    }

    pcap_close(session->pcap_handle);
    session->packet_ready_cb.Dispose();
}

void PcapSession::Fileno(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    PcapSession* session = ObjectWrap::Unwrap<PcapSession>(args.This());

    int fd = pcap_get_selectable_fd(session->pcap_handle);

    args.GetReturnValue().Set(Integer::NewFromUnsigned(fd));
}

void PcapSession::Stats(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    struct pcap_stat ps;

    PcapSession* session = ObjectWrap::Unwrap<PcapSession>(args.This());

    if (pcap_stats(session->pcap_handle, &ps) == -1) {
        isolate->ThrowException(Exception::Error(String::New("Error in pcap_stats")));
      return;
        // TODO - use pcap_geterr to figure out what the error was
    }

    Local<Object> stats_obj = Object::New();

    stats_obj->Set(String::New("ps_recv"), Integer::NewFromUnsigned(ps.ps_recv));
    stats_obj->Set(String::New("ps_drop"), Integer::NewFromUnsigned(ps.ps_drop));
    stats_obj->Set(String::New("ps_ifdrop"), Integer::NewFromUnsigned(ps.ps_ifdrop));
    // ps_ifdrop may not be supported on this platform, but there's no good way to tell, is there?

    args.GetReturnValue().Set(stats_obj);
}

void PcapSession::Inject(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    if (args.Length() != 1) {
        isolate->ThrowException(Exception::TypeError(String::New("Inject takes exactly one argument")));
      return;
    }

    if (!node::Buffer::HasInstance(args[0])) {
        isolate->ThrowException(Exception::TypeError(String::New("First argument must be a buffer")));
      return;
    }

    PcapSession* session = ObjectWrap::Unwrap<PcapSession>(args.This());
    char * bufferData = NULL;
    size_t bufferLength = 0;
#if NODE_VERSION_AT_LEAST(0,3,0)
    Local<Object> buffer_obj = args[0]->ToObject();
    bufferData = node::Buffer::Data(buffer_obj);
    bufferLength = node::Buffer::Length(buffer_obj);
#else
    node::Buffer *buffer_obj = ObjectWrap::Unwrap<node::Buffer>(args[0]->ToObject());
    bufferData = buffer_obj->data();
    bufferLength = buffer_obj->length();
#endif

    if (pcap_inject(session->pcap_handle, bufferData, bufferLength) != (int)bufferLength) {
        isolate->ThrowException(Exception::Error(String::New("Pcap inject failed.")));
      return;
    }
}

