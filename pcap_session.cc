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

void PcapSession::Init(Local<Object> exports) {
  Nan::HandleScope scope;
  // Prepare constructor template
  Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
  tpl->SetClassName(Nan::New("PcapSession").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  // Prototype
  Nan::SetPrototypeMethod(tpl, "open_live", OpenLive);
  Nan::SetPrototypeMethod(tpl, "open_offline", OpenOffline);
  Nan::SetPrototypeMethod(tpl, "dispatch", Dispatch);
  Nan::SetPrototypeMethod(tpl, "start_polling", StartPolling);
  Nan::SetPrototypeMethod(tpl, "close", Close);
  Nan::SetPrototypeMethod(tpl, "stats", Stats);
  Nan::SetPrototypeMethod(tpl, "inject", Inject);

  constructor.Reset(tpl->GetFunction(Nan::GetCurrentContext()).ToLocalChecked());
  Nan::Set(exports, Nan::New("PcapSession").ToLocalChecked(), tpl->GetFunction(Nan::GetCurrentContext()).ToLocalChecked());
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
    info.GetReturnValue().Set(Nan::NewInstance(cons).ToLocalChecked());
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

    Nan::Call(session->packet_ready_cb, 0, NULL);

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

    Local<Object> buffer_obj = info[0]->ToObject(Nan::GetCurrentContext()).FromMaybe(Local<v8::Object>());
    session->buffer_data = node::Buffer::Data(buffer_obj);
    session->buffer_length = node::Buffer::Length(buffer_obj);
    Local<Object> header_obj = info[1]->ToObject(Nan::GetCurrentContext()).FromMaybe(Local<v8::Object>());
    session->header_data = node::Buffer::Data(header_obj);

    int packet_count;
    do {
        packet_count = pcap_dispatch(session->pcap_handle, 1, PacketReady, (u_char *)session);

        if (packet_count == -2) {
            FinalizeClose(session);
        }
    } while (packet_count > 0);

    info.GetReturnValue().Set(Nan::New<Integer>(packet_count));
}

void PcapSession::Open(bool live, const Nan::FunctionCallbackInfo<Value>& info)
{
    Nan::HandleScope scope;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (info.Length() == 10) {
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
        if (!info[3]->IsInt32()) {
            Nan::ThrowTypeError("pcap Open: info[3] must be a Number");
            return;
        }
        if (!info[4]->IsString()) {
            Nan::ThrowTypeError("pcap Open: info[4] must be a String");
            return;
        }
        if (!info[5]->IsFunction()) {
            Nan::ThrowTypeError("pcap Open: info[5] must be a Function");
            return;
        }
        if (!info[6]->IsBoolean()) {
            Nan::ThrowTypeError("pcap Open: info[6] must be a Boolean");
            return;
        }
        if (!info[7]->IsInt32()) {
            Nan::ThrowTypeError("pcap Open: info[7] must be a Number");
            return;
        }
        if (!info[8]->IsFunction()) { // warning function
            Nan::ThrowTypeError("pcap Open: info[8] must be a Function");
            return;
        }
        if (!info[9]->IsBoolean()) {
            Nan::ThrowTypeError("pcap Open: info[9] must be a Boolean");
            return;
        }
    } else {
        Nan::ThrowTypeError("pcap Open: expecting 8 arguments");
        return;
    }
    Nan::Utf8String device(info[0]->ToString(Nan::GetCurrentContext()).FromMaybe(Local<v8::String>()));
    Nan::Utf8String filter(info[1]->ToString(Nan::GetCurrentContext()).FromMaybe(Local<v8::String>()));
    int buffer_size = Nan::To<int32_t>(info[2]).FromJust();
    int snap_length = Nan::To<int32_t>(info[3]).FromJust();
    int buffer_timeout = Nan::To<int32_t>(info[7]).FromJust();
    Nan::Utf8String pcap_output_filename(info[4]->ToString(Nan::GetCurrentContext()).FromMaybe(Local<v8::String>()));

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.This());

    session->packet_ready_cb.SetFunction(info[5].As<Function>());
    session->pcap_dump_handle = NULL;

    if (live) {
        if (pcap_lookupnet((char *) *device, &session->net, &session->mask, errbuf) == -1) {
            session->net = 0;
            session->mask = 0;
            Local<Value> str = Nan::New(errbuf).ToLocalChecked();
            Nan::Call(info[8].As<Function>(), Nan::GetCurrentContext()->Global(), 1, &str);
        }

        session->pcap_handle = pcap_create((char *) *device, errbuf);
        if (session->pcap_handle == NULL) {
            Nan::ThrowError(errbuf);
            return;
        }

        // 64KB is the max IPv4 packet size
        if (pcap_set_snaplen(session->pcap_handle, snap_length) != 0) {
            Nan::ThrowError("error setting snaplen");
            return;
        }

        if (Nan::To<int32_t>(info[9]).FromJust()) {
            if (pcap_set_promisc(session->pcap_handle, 1) != 0) {
                Nan::ThrowError("error setting promiscuous mode");
                return;
            }
        }

        // Try to set buffer size.  Sometimes the OS has a lower limit that it will silently enforce.
        if (pcap_set_buffer_size(session->pcap_handle, buffer_size) != 0) {
            Nan::ThrowError("error setting buffer size");
            return;
        }

        if (buffer_timeout > 0) {
            // set "timeout" on read, even though we are also setting nonblock below.  On Linux this is required.
            if (pcap_set_timeout(session->pcap_handle, buffer_timeout) != 0) {
                Nan::ThrowError("error setting read timeout");
                return;
            }
        }

        // timeout <= 0 is undefined behaviour, we'll set immediate mode instead. (timeout is ignored in immediate mode)
        if (pcap_set_immediate_mode(session->pcap_handle, (buffer_timeout <= 0)) != 0) {
            Nan::ThrowError("error setting immediate mode");
            return;
        }

        if (Nan::To<int32_t>(info[6]).FromJust()) {
            if (pcap_set_rfmon(session->pcap_handle, 1) != 0) {
                Nan::ThrowError(pcap_geterr(session->pcap_handle));
                return;
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
    if (fd < 0) {
        Nan::ThrowError(pcap_geterr(session->pcap_handle));
        return;
    }
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

    if (session->pcap_handle != NULL) {
        pcap_breakloop(session->pcap_handle);
    }
}

void PcapSession::FinalizeClose(PcapSession * session) {
    if (session->poll_init) {
        uv_poll_stop(&session->poll_handle);
        uv_unref((uv_handle_t*) &session->poll_handle);
        session->poll_init = false;
        delete session->poll_resource;
    }

    pcap_close(session->pcap_handle);
    session->pcap_handle = NULL;

    session->packet_ready_cb.Reset();
}

void PcapSession::poll_handler(uv_poll_t* handle, int status, int events)
{
    Nan::HandleScope scope;
    PcapSession* session = reinterpret_cast<PcapSession*>(handle->data);

    Local<String> callback_symbol = Nan::New("read_callback").ToLocalChecked();
    Local<Value> callback_v = Nan::Get(session->handle(), callback_symbol).ToLocalChecked();
    if(!callback_v->IsFunction()) return;
    Local<Function> callback = Local<Function>::Cast(callback_v);

    Nan::TryCatch try_catch;

    session->poll_resource->runInAsyncScope(Nan::GetCurrentContext()->Global(), callback, 0, NULL);

    if (try_catch.HasCaught())
        Nan::FatalException(try_catch);
}

void PcapSession::StartPolling(const Nan::FunctionCallbackInfo<Value>& info)
{
    Nan::HandleScope scope;

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.Holder());
    if (session->poll_init) return;

    if (session->pcap_handle == NULL) {
        Nan::ThrowError("Error: pcap session already closed");
        return;
    }

    int fd = pcap_get_selectable_fd(session->pcap_handle);
    if (fd < 0) {
        Nan::ThrowError(pcap_geterr(session->pcap_handle));
        return;
    }

    session->poll_handle.data = session;
    if (uv_poll_init(Nan::GetCurrentEventLoop(), &session->poll_handle, fd) < 0) {
        Nan::ThrowError("Couldn't initialize UV poll");
        return;
    }
    session->poll_init = true;

    if (uv_poll_start(&session->poll_handle, UV_READABLE, poll_handler) < 0) {
        Nan::ThrowError("Couldn't start UV poll");
        return;
    }
    uv_ref((uv_handle_t*) &session->poll_handle);

    session->poll_resource = new Nan::AsyncResource("pcap:PcapSession", info.Holder());
}

void PcapSession::Stats(const Nan::FunctionCallbackInfo<Value>& info)
{
    Nan::HandleScope scope;

    struct pcap_stat ps;

    PcapSession* session = Nan::ObjectWrap::Unwrap<PcapSession>(info.Holder());

    if (session->pcap_handle == NULL) {
        Nan::ThrowError("Error: pcap session already closed");
        return;
    }

    if (pcap_stats(session->pcap_handle, &ps) == -1) {
        Nan::ThrowError("Error in pcap_stats");
        return;
        // TODO - use pcap_geterr to figure out what the error was
    }

    Local<Object> stats_obj = Nan::New<Object>();

    Nan::Set(stats_obj, Nan::New("ps_recv").ToLocalChecked(), Nan::New<Integer>(ps.ps_recv));
    Nan::Set(stats_obj, Nan::New("ps_drop").ToLocalChecked(), Nan::New<Integer>(ps.ps_drop));
    Nan::Set(stats_obj, Nan::New("ps_ifdrop").ToLocalChecked(), Nan::New<Integer>(ps.ps_ifdrop));
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

    if (session->pcap_handle == NULL) {
        Nan::ThrowError("Error: pcap session already closed");
        return;
    }

    char * bufferData = NULL;
    size_t bufferLength = 0;
    Local<Object> buffer_obj = info[0]->ToObject(Nan::GetCurrentContext()).FromMaybe(Local<v8::Object>());
    bufferData = node::Buffer::Data(buffer_obj);
    bufferLength = node::Buffer::Length(buffer_obj);

    if (pcap_inject(session->pcap_handle, bufferData, bufferLength) != (int)bufferLength) {
        Nan::ThrowError("Pcap inject failed.");
        return;
    }
    return;
}
