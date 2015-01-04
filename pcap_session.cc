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
  NanScope();
  // Prepare constructor template
  Local<FunctionTemplate> tpl = NanNew<FunctionTemplate>(New);
  tpl->SetClassName(NanNew("PcapSession"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  // Prototype
  NODE_SET_PROTOTYPE_METHOD(tpl, "open_live", OpenLive);
  NODE_SET_PROTOTYPE_METHOD(tpl, "open_offline", OpenOffline);
  NODE_SET_PROTOTYPE_METHOD(tpl, "dispatch", Dispatch);
  NODE_SET_PROTOTYPE_METHOD(tpl, "fileno", Fileno);
  NODE_SET_PROTOTYPE_METHOD(tpl, "close", Close);
  NODE_SET_PROTOTYPE_METHOD(tpl, "stats", Stats);
  NODE_SET_PROTOTYPE_METHOD(tpl, "inject", Inject);

  NanAssignPersistent(constructor, tpl->GetFunction());
  exports->Set(NanNew("PcapSession"), tpl->GetFunction());
}

NAN_METHOD(PcapSession::New) {
  NanScope();

  if (args.IsConstructCall()) {
    // Invoked as constructor: `new MyObject(...)`
    PcapSession* obj = new PcapSession();
    obj->Wrap(args.This());
    NanReturnValue(args.This());
  } else {
    // Invoked as plain function `MyObject(...)`, turn into construct call.
    Local<Function> cons = NanNew<Function>(constructor);
    NanReturnValue(cons->NewInstance());
  }
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
    NanScope();

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

    Local<Object> packet_header = NanNew<Object>();

    packet_header->Set(NanNew("tv_sec"), NanNew<Integer>(pkthdr->ts.tv_sec));
    packet_header->Set(NanNew("tv_usec"), NanNew<Integer>(pkthdr->ts.tv_usec));
    packet_header->Set(NanNew("caplen"), NanNew<Integer>(pkthdr->caplen));
    packet_header->Set(NanNew("len"), NanNew<Integer>(pkthdr->len));

    Local<Value> argv[1] = { packet_header };

    NanMakeCallback(NanGetCurrentContext()->Global(), NanNew(session->packet_ready_cb), 1, argv);

    if (try_catch.HasCaught())  {
        node::FatalException(try_catch);
    }
}

NAN_METHOD(PcapSession::Dispatch)
{
    NanScope();

    if (args.Length() != 1) {
        NanThrowTypeError("Dispatch takes exactly one arguments");
        NanReturnUndefined();
    }

    if (!node::Buffer::HasInstance(args[0])) {
        NanThrowTypeError("First argument must be a buffer");
        NanReturnUndefined();
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

    NanReturnValue(NanNew<Integer>(packet_count));
}

_NAN_METHOD_RETURN_TYPE PcapSession::Open(bool live, const FunctionCallbackInfo<Value>& args)
{
    NanScope();
    char errbuf[PCAP_ERRBUF_SIZE];

    if (args.Length() == 5 || args.Length() == 6) {
        if (!args[0]->IsString()) {
            NanThrowTypeError("pcap Open: args[0] must be a String");
            NanReturnUndefined();
        }
        if (!args[1]->IsString()) {
            NanThrowTypeError("pcap Open: args[1] must be a String");
            NanReturnUndefined();
        }
        if (!args[2]->IsInt32()) {
            NanThrowTypeError("pcap Open: args[2] must be a Number");
            NanReturnUndefined();
        }
        if (!args[3]->IsString()) {
            NanThrowTypeError("pcap Open: args[3] must be a String");
            NanReturnUndefined();
        }
        if (!args[4]->IsFunction()) {
            NanThrowTypeError("pcap Open: args[4] must be a Function");
            NanReturnUndefined();
        }
        if (args.Length() == 6) {
            if (!args[5]->IsBoolean()) {
                NanThrowTypeError("pcap Open: args[5] must be a Boolean");
                NanReturnUndefined();
            }
        }
    } else {
        NanThrowTypeError("pcap Open: expecting 4 arguments");
        NanReturnUndefined();
    }
    NanUtf8String device(args[0]->ToString());
    NanUtf8String filter(args[1]->ToString());
    int buffer_size = args[2]->Int32Value();
    NanUtf8String pcap_output_filename(args[3]->ToString());

    PcapSession* session = ObjectWrap::Unwrap<PcapSession>(args.This());

    NanAssignPersistent(session->packet_ready_cb, args[4].As<Function>());
    session->pcap_dump_handle = NULL;

    if (live) {
        if (pcap_lookupnet((char *) *device, &session->net, &session->mask, errbuf) == -1) {
            session->net = 0;
            session->mask = 0;
            fprintf(stderr, "warning: %s - this may not actually work\n", errbuf);
        }

        session->pcap_handle = pcap_create((char *) *device, errbuf);
        if (session->pcap_handle == NULL) {
            NanThrowError(errbuf);
            NanReturnUndefined();
        }

        // 64KB is the max IPv4 packet size
        if (pcap_set_snaplen(session->pcap_handle, 65535) != 0) {
            NanThrowError("error setting snaplen");
            NanReturnUndefined();
        }

        // always use promiscuous mode
        if (pcap_set_promisc(session->pcap_handle, 1) != 0) {
            NanThrowError("error setting promiscuous mode");
            NanReturnUndefined();
        }

        // Try to set buffer size.  Sometimes the OS has a lower limit that it will silently enforce.
        if (pcap_set_buffer_size(session->pcap_handle, buffer_size) != 0) {
            NanThrowError("error setting buffer size");
            NanReturnUndefined();
        }

        // set "timeout" on read, even though we are also setting nonblock below.  On Linux this is required.
        if (pcap_set_timeout(session->pcap_handle, 1000) != 0) {
            NanThrowError("error setting read timeout");
            NanReturnUndefined();
        }

        // fixes a previous to-do that was here.
        if (args.Length() == 6) {
            if (args[5]->Int32Value()) {
                if (pcap_set_rfmon(session->pcap_handle, 1) != 0) {
                    NanThrowError(pcap_geterr(session->pcap_handle));
                    NanReturnUndefined();
                }
            }
        }

        if (pcap_activate(session->pcap_handle) != 0) {
            NanThrowError(pcap_geterr(session->pcap_handle));
            NanReturnUndefined();
        }

        if (strlen((char *) *pcap_output_filename) > 0) {
            session->pcap_dump_handle = pcap_dump_open(session->pcap_handle, (char *) *pcap_output_filename);
            if (session->pcap_dump_handle == NULL) {
                NanThrowError("error opening dump");
                NanReturnUndefined();
            }
        }

        if (pcap_setnonblock(session->pcap_handle, 1, errbuf) == -1) {
          NanThrowError(errbuf);
          NanReturnUndefined();
        }
    } else {
        // Device is the path to the savefile
        session->pcap_handle = pcap_open_offline((char *) *device, errbuf);
        if (session->pcap_handle == NULL) {
            NanThrowError(errbuf);
            NanReturnUndefined();
        }
    }

    if (filter.length() != 0) {
      if (pcap_compile(session->pcap_handle, &session->fp, (char *) *filter, 1, session->net) == -1) {
        NanThrowError(pcap_geterr(session->pcap_handle));
        NanReturnUndefined();
      }

      if (pcap_setfilter(session->pcap_handle, &session->fp) == -1) {
        NanThrowError(pcap_geterr(session->pcap_handle));
        NanReturnUndefined();
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
        ret = NanNew("LINKTYPE_NULL");
        break;
    case DLT_EN10MB: // most wifi interfaces pretend to be "ethernet"
        ret =  NanNew("LINKTYPE_ETHERNET");
        break;
    case DLT_IEEE802_11_RADIO: // 802.11 "monitor mode"
        ret = NanNew("LINKTYPE_IEEE802_11_RADIO");
        break;
    case DLT_RAW: // "raw IP"
        ret = NanNew("LINKTYPE_RAW");
        break;
    case DLT_LINUX_SLL: // "Linux cooked capture"
        ret = NanNew("LINKTYPE_LINUX_SLL");
        break;
    default:
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unknown linktype %d", link_type);
        ret = NanNew(errbuf);
        break;
    }
    NanReturnValue(ret);
}

NAN_METHOD(PcapSession::OpenLive)
{
    return Open(true, args);
}

NAN_METHOD(PcapSession::OpenOffline)
{
    return Open(false, args);
}

NAN_METHOD(PcapSession::Close)
{
    NanScope();

    PcapSession* session = ObjectWrap::Unwrap<PcapSession>(args.This());

    if (session->pcap_dump_handle != NULL) {
        pcap_dump_close(session->pcap_dump_handle);
        session->pcap_dump_handle = NULL;
    }

    pcap_close(session->pcap_handle);
    NanDisposePersistent(session->packet_ready_cb);
    NanReturnUndefined();
}

NAN_METHOD(PcapSession::Fileno)
{
    NanScope();

    PcapSession* session = ObjectWrap::Unwrap<PcapSession>(args.This());

    int fd = pcap_get_selectable_fd(session->pcap_handle);

    NanReturnValue(NanNew<Integer>(fd));
}

NAN_METHOD(PcapSession::Stats)
{
    NanScope();

    struct pcap_stat ps;

    PcapSession* session = ObjectWrap::Unwrap<PcapSession>(args.This());

    if (pcap_stats(session->pcap_handle, &ps) == -1) {
        NanThrowError("Error in pcap_stats");
        return;
        // TODO - use pcap_geterr to figure out what the error was
    }

    Local<Object> stats_obj = NanNew<Object>();

    stats_obj->Set(NanNew("ps_recv"), NanNew<Integer>(ps.ps_recv));
    stats_obj->Set(NanNew("ps_drop"), NanNew<Integer>(ps.ps_drop));
    stats_obj->Set(NanNew("ps_ifdrop"), NanNew<Integer>(ps.ps_ifdrop));
    // ps_ifdrop may not be supported on this platform, but there's no good way to tell, is there?

    NanReturnValue(stats_obj);
}

NAN_METHOD(PcapSession::Inject)
{
    NanScope();

    if (args.Length() != 1) {
        NanThrowTypeError("Inject takes exactly one argument");
        NanReturnUndefined();
    }

    if (!node::Buffer::HasInstance(args[0])) {
        NanThrowTypeError("First argument must be a buffer");
        NanReturnUndefined();
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
        NanThrowError("Pcap inject failed.");
        NanReturnUndefined();
    }
    NanReturnUndefined();
}

