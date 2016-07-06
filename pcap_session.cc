#include <assert.h>
#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <cstring>
#include <string.h>

#include "pcap_session.h"

using namespace v8;

Nan::Persistent<Function> PcapSession::constructor;

PcapSession::PcapSession() {};
PcapSession::~PcapSession() {};

void PcapSession::Init(Handle<Object> exports) {
  Nan::HandleScope scope;
  // Prepare constructor template
  Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
  tpl->SetClassName(Nan::New("PcapSession").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  // Prototype
  Nan::SetPrototypeMethod(tpl, "open_live", OpenLive);
  Nan::SetPrototypeMethod(tpl, "open_offline", OpenOffline);
  Nan::SetPrototypeMethod(tpl, "dispatch", Dispatch);
  Nan::SetPrototypeMethod(tpl, "fileno", Fileno);
  Nan::SetPrototypeMethod(tpl, "close", Close);
  Nan::SetPrototypeMethod(tpl, "stats", Stats);
  Nan::SetPrototypeMethod(tpl, "inject", Inject);

  constructor.Reset(tpl->GetFunction());
  exports->Set(Nan::New("PcapSession").ToLocalChecked(), tpl->GetFunction());
}

void PcapSession::New(const Nan::FunctionCallbackInfo<Value>& info) {
  Nan::HandleScope scope;
  if (info.IsConstructCall()) {
    // Invoked as constructor: `new MyObject(...)`
    PcapSession* obj = new PcapSession();
    obj->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  } else {
    // Invoked as plain function `MyObject(...)`, turn into construct call.
    Local<Function> cons = Nan::New<Function>(constructor);
    info.GetReturnValue().Set(cons->NewInstance());
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
    Nan::HandleScope scope;

    PcapSession* session = (PcapSession *)s;

    if (session->pcap_dump_handle != NULL) {
        pcap_dump((u_char *) session->pcap_dump_handle, pkthdr, packet);
    }

    size_t copy_len = pkthdr->caplen;
    if (copy_len > session->buffer_length) {
        copy_len = session->buffer_length;
    }
    memcpy(session->buffer_data, packet, copy_len);

    // copy header data to fixed offsets in second buffer from user
    memcpy(session->header_data, &(pkthdr->ts.tv_sec), 4);
    memcpy(session->header_data + 4, &(pkthdr->ts.tv_usec), 4);
    memcpy(session->header_data + 8, &(pkthdr->caplen), 4);
    memcpy(session->header_data + 12, &(pkthdr->len), 4);

    Nan::TryCatch try_catch;

    Nan::MakeCallback(Nan::GetCurrentContext()->Global(), Nan::New(session->packet_ready_cb), 0, NULL);

    if (try_catch.HasCaught())  {
        Nan::FatalException(try_catch);
    }
}

void PcapSession::Dispatch(const Nan::FunctionCallbackInfo<Value>& info)
{
    Nan::HandleScope scope;

    if (info.Length() != 2) {
        Nan::ThrowTypeError("Dispatch takes exactly two arguments");
        return;
    }

    if (!node::Buffer::HasInstance(info[0])) {
        Nan::ThrowTypeError("First argument must be a buffer");
        return;
    }

    if (!node::Buffer::HasInstance(info[1])) {
        Nan::ThrowTypeError("Second argument must be a buffer");
        return;
    }

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.This());

    Local<Object> buffer_obj = info[0]->ToObject();
    session->buffer_data = node::Buffer::Data(buffer_obj);
    session->buffer_length = node::Buffer::Length(buffer_obj);
    Local<Object> header_obj = info[1]->ToObject();
    session->header_data = node::Buffer::Data(header_obj);

    int packet_count;
    do {
        packet_count = pcap_dispatch(session->pcap_handle, 1, PacketReady, (u_char *)session);
    } while (packet_count > 0);

    info.GetReturnValue().Set(Nan::New<Integer>(packet_count));
}

void PcapSession::Open(bool live, const Nan::FunctionCallbackInfo<Value>& info)
{
    Nan::HandleScope scope;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (info.Length() == 6) {
        if (!info[0]->IsString()) {
            Nan::ThrowTypeError("pcap Open: info[0] must be a String");
            return;
        }
        if (!info[1]->IsString()) {
            Nan::ThrowTypeError("pcap Open: info[1] must be a String");
            return;
        }
        if (!info[2]->IsInt32()) {
            Nan::ThrowTypeError("pcap Open: info[2] must be a Number");
            return;
        }
        if (!info[3]->IsString()) {
            Nan::ThrowTypeError("pcap Open: info[3] must be a String");
            return;
        }
        if (!info[4]->IsFunction()) {
            Nan::ThrowTypeError("pcap Open: info[4] must be a Function");
            return;
        }
        if (!info[5]->IsBoolean()) {
            Nan::ThrowTypeError("pcap Open: info[5] must be a Boolean");
            return;
        }
    } else {
        Nan::ThrowTypeError("pcap Open: expecting 6 arguments");
        return;
    }
    Nan::Utf8String device(info[0]->ToString());
    Nan::Utf8String filter(info[1]->ToString());
    int buffer_size = info[2]->Int32Value();
    Nan::Utf8String pcap_output_filename(info[3]->ToString());

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.This());

    session->packet_ready_cb.Reset(info[4].As<Function>());
    session->pcap_dump_handle = NULL;

    if (live) {
        if (pcap_lookupnet((char *) *device, &session->net, &session->mask, errbuf) == -1) {
            session->net = 0;
            session->mask = 0;
            fprintf(stderr, "warning: %s - this may not actually work\n", errbuf);
        }

        session->pcap_handle = pcap_create((char *) *device, errbuf);
        if (session->pcap_handle == NULL) {
            Nan::ThrowError(errbuf);
            return;
        }

        // 64KB is the max IPv4 packet size
        if (pcap_set_snaplen(session->pcap_handle, 65535) != 0) {
            Nan::ThrowError("error setting snaplen");
            return;
        }

        // always use promiscuous mode
        if (pcap_set_promisc(session->pcap_handle, 1) != 0) {
            Nan::ThrowError("error setting promiscuous mode");
            return;
        }

        // Try to set buffer size.  Sometimes the OS has a lower limit that it will silently enforce.
        if (pcap_set_buffer_size(session->pcap_handle, buffer_size) != 0) {
            Nan::ThrowError("error setting buffer size");
            return;
        }

        // set "timeout" on read, even though we are also setting nonblock below.  On Linux this is required.
        if (pcap_set_timeout(session->pcap_handle, 1000) != 0) {
            Nan::ThrowError("error setting read timeout");
            return;
        }

        // fixes a previous to-do that was here.
        if (info.Length() == 6) {
            if (info[5]->Int32Value()) {
                if (pcap_set_rfmon(session->pcap_handle, 1) != 0) {
                    Nan::ThrowError(pcap_geterr(session->pcap_handle));
                    return;
                }
            }
        }

        if (pcap_activate(session->pcap_handle) != 0) {
            Nan::ThrowError(pcap_geterr(session->pcap_handle));
            return;
        }

        if (strlen((char *) *pcap_output_filename) > 0) {
            session->pcap_dump_handle = pcap_dump_open(session->pcap_handle, (char *) *pcap_output_filename);
            if (session->pcap_dump_handle == NULL) {
                Nan::ThrowError("error opening dump");
                return;
            }
        }

        if (pcap_setnonblock(session->pcap_handle, 1, errbuf) == -1) {
          Nan::ThrowError(errbuf);
          return;
        }
    } else {
        // Device is the path to the savefile
        session->pcap_handle = pcap_open_offline((char *) *device, errbuf);
        if (session->pcap_handle == NULL) {
            Nan::ThrowError(errbuf);
            return;
        }
    }

    if (filter.length() != 0) {
      if (pcap_compile(session->pcap_handle, &session->fp, (char *) *filter, 1, session->net) == -1) {
        Nan::ThrowError(pcap_geterr(session->pcap_handle));
        return;
      }

      if (pcap_setfilter(session->pcap_handle, &session->fp) == -1) {
        Nan::ThrowError(pcap_geterr(session->pcap_handle));
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
        ret = Nan::New("LINKTYPE_NULL").ToLocalChecked();
        break;
    case DLT_EN10MB: // most wifi interfaces pretend to be "ethernet"
        ret =  Nan::New("LINKTYPE_ETHERNET").ToLocalChecked();
        break;
    case DLT_IEEE802_11_RADIO: // 802.11 "monitor mode"
        ret = Nan::New("LINKTYPE_IEEE802_11_RADIO").ToLocalChecked();
        break;
    case DLT_RAW: // "raw IP"
        ret = Nan::New("LINKTYPE_RAW").ToLocalChecked();
        break;
    case DLT_LINUX_SLL: // "Linux cooked capture"
        ret = Nan::New("LINKTYPE_LINUX_SLL").ToLocalChecked();
        break;
    default:
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unknown linktype %d", link_type);
        ret = Nan::New(errbuf).ToLocalChecked();
        break;
    }
    info.GetReturnValue().Set(ret);
}

void PcapSession::OpenLive(const Nan::FunctionCallbackInfo<Value>& info)
{
    return Open(true, info);
}

void PcapSession::OpenOffline(const Nan::FunctionCallbackInfo<Value>& info)
{
    return Open(false, info);
}

void PcapSession::Close(const Nan::FunctionCallbackInfo<Value>& info)
{
    Nan::HandleScope scope;

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.Holder());

    if (session->pcap_dump_handle != NULL) {
        pcap_dump_close(session->pcap_dump_handle);
        session->pcap_dump_handle = NULL;
    }

    pcap_close(session->pcap_handle);
    session->packet_ready_cb.Reset();
    return;
}

void PcapSession::Fileno(const Nan::FunctionCallbackInfo<Value>& info)
{
    Nan::HandleScope scope;

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.Holder());

    int fd = pcap_get_selectable_fd(session->pcap_handle);

    info.GetReturnValue().Set(Nan::New<Integer>(fd));
}

void PcapSession::Stats(const Nan::FunctionCallbackInfo<Value>& info)
{
    Nan::HandleScope scope;

    struct pcap_stat ps;

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.Holder());

    if (pcap_stats(session->pcap_handle, &ps) == -1) {
        Nan::ThrowError("Error in pcap_stats");
        return;
        // TODO - use pcap_geterr to figure out what the error was
    }

    Local<Object> stats_obj = Nan::New<Object>();

    stats_obj->Set(Nan::New("ps_recv").ToLocalChecked(), Nan::New<Integer>(ps.ps_recv));
    stats_obj->Set(Nan::New("ps_drop").ToLocalChecked(), Nan::New<Integer>(ps.ps_drop));
    stats_obj->Set(Nan::New("ps_ifdrop").ToLocalChecked(), Nan::New<Integer>(ps.ps_ifdrop));
    // ps_ifdrop may not be supported on this platform, but there's no good way to tell, is there?

    info.GetReturnValue().Set(stats_obj);
}

void PcapSession::Inject(const Nan::FunctionCallbackInfo<Value>& info)
{
    Nan::HandleScope scope;

    if (info.Length() != 1) {
        Nan::ThrowTypeError("Inject takes exactly one argument");
        return;
    }

    if (!node::Buffer::HasInstance(info[0])) {
        Nan::ThrowTypeError("First argument must be a buffer");
        return;
    }

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.Holder());
    char * bufferData = NULL;
    size_t bufferLength = 0;
    Local<Object> buffer_obj = info[0]->ToObject();
    bufferData = node::Buffer::Data(buffer_obj);
    bufferLength = node::Buffer::Length(buffer_obj);

    if (pcap_inject(session->pcap_handle, bufferData, bufferLength) != (int)bufferLength) {
        Nan::ThrowError("Pcap inject failed.");
        return;
    }
    return;
}
