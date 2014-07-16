#ifndef PCAP_SESSION_H
#define PCAP_SESSION_H

#include <node.h>
#include <node_object_wrap.h>
#include <pcap/pcap.h>

class PcapSession : public node::ObjectWrap {
public:
    static void Init(v8::Handle<v8::Object> exports);

private:
    PcapSession();
    ~PcapSession();

    static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void Open(bool live, const v8::FunctionCallbackInfo<v8::Value>& args);
    static void OpenLive(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void OpenOffline(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void Dispatch(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void Fileno(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void Close(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void Stats(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void Inject(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void PacketReady(u_char *callback_p, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    v8::Persistent<v8::Function> packet_ready_cb;
    static v8::Persistent<v8::Function> constructor;

    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t *pcap_handle;
    pcap_dumper_t *pcap_dump_handle;
    char *buffer_data;
    size_t buffer_length;
};

#endif
