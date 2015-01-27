#ifndef PCAP_SESSION_H
#define PCAP_SESSION_H

#include <node.h>
#include <pcap/pcap.h>

class PcapSession : public node::ObjectWrap {
public:
    static void Init(v8::Handle<v8::Object> exports);

private:
    PcapSession();
    ~PcapSession();

    static v8::Handle<v8::Value> New(const v8::Arguments& args);
    static v8::Handle<v8::Value> Open(bool live, const v8::Arguments& args);
    static v8::Handle<v8::Value> OpenLive(const v8::Arguments& args);
    static v8::Handle<v8::Value> OpenOffline(const v8::Arguments& args);
    static v8::Handle<v8::Value> Dispatch(const v8::Arguments& args);
    static v8::Handle<v8::Value> Fileno(const v8::Arguments& args);
    static v8::Handle<v8::Value> Close(const v8::Arguments& args);
    static v8::Handle<v8::Value> Stats(const v8::Arguments& args);
    static v8::Handle<v8::Value> Inject(const v8::Arguments& args);
    static void PacketReady(u_char *callback_p, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    v8::Persistent<v8::Function> packet_ready_cb;

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
