#ifndef PCAP_SESSION_H
#define PCAP_SESSION_H

#include <nan.h>
#include <pcap/pcap.h>

class PcapSession : public Nan::ObjectWrap {
public:
    static void Init(v8::Handle<v8::Object> exports);

private:
    PcapSession();
    ~PcapSession();

    static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Open(bool live, const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void OpenLive(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void OpenOffline(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Dispatch(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Fileno(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Close(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Stats(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Inject(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void PacketReady(u_char *callback_p, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    Nan::Persistent<v8::Function> packet_ready_cb;
    static Nan::Persistent<v8::Function> constructor;

    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t *pcap_handle;
    pcap_dumper_t *pcap_dump_handle;
    char *buffer_data;
    size_t buffer_length;
    char *header_data;
};

#endif
