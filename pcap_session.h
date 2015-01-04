#ifndef PCAP_SESSION_H
#define PCAP_SESSION_H

#include <nan.h>
#include <pcap/pcap.h>

class PcapSession : public node::ObjectWrap {
public:
    static void Init(v8::Handle<v8::Object> exports);

private:
    PcapSession();
    ~PcapSession();

    static NAN_METHOD(New);
    static _NAN_METHOD_RETURN_TYPE Open(bool live, _NAN_METHOD_ARGS);
    static NAN_METHOD(OpenLive);
    static NAN_METHOD(OpenOffline);
    static NAN_METHOD(Dispatch);
    static NAN_METHOD(Fileno);
    static NAN_METHOD(Close);
    static NAN_METHOD(Stats);
    static NAN_METHOD(Inject);
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
