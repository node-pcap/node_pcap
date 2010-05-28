#include <node.h>
#include <node_events.h>
#include <node_buffer.h>
#include <assert.h>
#include <pcap/pcap.h>
#include <v8.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ev.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

using namespace v8;
using namespace node;

// These things need to be moved into a class, so each instance can have its own session.
// Right now, there can only be one pcap session at a time.
struct bpf_program fp;
bpf_u_int32 mask;
bpf_u_int32 net;
pcap_t *pcap_handle;
Buffer *buffer;

// PacketReady is called from within pcap, still on the stack of Dispatch.  It should be called
// only one time per Dispatch, but sometimes it gets called 0 times.  PacketReady invokes the
// JS callback associated with the dispatch() call in JS.
//
// Stack:
// 1. readWatcher.callback (pcap.js)
// 2. binding.dispatch (pcap.js)
// 3. Dispatch (binding.cc)
// 4. pcap_dispatch (libpcap)
// 5. PacketReady (binding.cc)
// 6. binding.dispatch callback (pcap.js)
//
void PacketReady(u_char *callback_p, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    HandleScope scope;

    Local<Function> * callback = (Local<Function>*)callback_p;

    // TODO - bounds checking
    memcpy(buffer->data(), packet, pkthdr->caplen);

    TryCatch try_catch;

    Local<Object> packet_header = Object::New();

    double t_ms = (pkthdr->ts.tv_sec * 1000) + (pkthdr->ts.tv_usec / 1000);

    packet_header->Set(String::New("time"), Date::New(t_ms));
    packet_header->Set(String::New("tv_sec"), Integer::NewFromUnsigned(pkthdr->ts.tv_sec));
    packet_header->Set(String::New("tv_usec"), Integer::NewFromUnsigned(pkthdr->ts.tv_usec));
    packet_header->Set(String::New("caplen"), Integer::NewFromUnsigned(pkthdr->caplen));
    packet_header->Set(String::New("len"), Integer::NewFromUnsigned(pkthdr->len));

    Local<Value> argv[1] = { packet_header };

    (*callback)->Call(Context::GetCurrent()->Global(), 1, argv);

    if (try_catch.HasCaught())  {
        FatalException(try_catch);
    }
}

Handle<Value>
Dispatch(const Arguments& args)
{
    HandleScope scope;

    if (args.Length() != 2) {
        return ThrowException(Exception::TypeError(String::New("Dispatch takes exactly two arguments")));
    }

    if (!Buffer::HasInstance(args[0])) {
        return ThrowException(Exception::TypeError(String::New("First argument must be a buffer")));
    }

    if (!args[1]->IsFunction()) {
        return ThrowException(Exception::TypeError(String::New("Second argument must be a function")));
    }

    Local<Function> callback = Local<Function>::Cast(args[1]);

    buffer = ObjectWrap::Unwrap<Buffer>(args[0]->ToObject());

    int packet_count, total_packets = 0;
    do {
        packet_count = pcap_dispatch(pcap_handle, 1, PacketReady, (u_char *)&callback);
        total_packets += packet_count;
    } while (packet_count > 0);

    return scope.Close(Integer::NewFromUnsigned(total_packets));
}

Handle<Value>
OpenLive(const Arguments& args)
{
    HandleScope scope;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (args.Length() != 2 || !args[0]->IsString() || !args[1]->IsString()) {
        return ThrowException(Exception::TypeError(String::New("Bad arguments")));
    }
    String::Utf8Value device(args[0]->ToString());
    String::Utf8Value filter(args[1]->ToString());

    // TODO - check for empty device string and look up default device

    if (pcap_lookupnet((char *) *device, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
        fprintf(stderr, "warning: %s - filtering may not work right\n", errbuf);
    }

    // 64KB is the max IPv4 packet size, 1 is promiscuous mode, 1000ms "read timeout" which sometimes does something good
    pcap_handle = pcap_open_live((char *) *device, 65535, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        return ThrowException(Exception::Error(String::New(errbuf)));
    }

    if (pcap_setnonblock(pcap_handle, 1, errbuf) == -1) {
        return ThrowException(Exception::Error(String::New(errbuf)));
    }

    if (pcap_compile(pcap_handle, &fp, (char *) *filter, 1, net) == -1) {
        return ThrowException(Exception::Error(String::New(pcap_geterr(pcap_handle))));
    }

    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        return ThrowException(Exception::Error(String::New(pcap_geterr(pcap_handle))));
    }

    int fd = pcap_get_selectable_fd(pcap_handle);

    // Work around buffering bug in BPF on OSX 10.6 as of May 19, 2010
    // This may result in dropped packets under load because it disables the (broken) buffer
    // http://seclists.org/tcpdump/2010/q1/110
#if defined(__APPLE_CC__) || defined(__APPLE__)
    #include <net/bpf.h>
    int v = 1;
    ioctl(fd, BIOCIMMEDIATE, &v);
    // TODO - check return value
#endif

    int link_type = pcap_datalink(pcap_handle);

    Local<Value> ret;
    switch (link_type) {
    case DLT_NULL:
        ret = String::New("LINKTYPE_NULL");
        break;
    case DLT_EN10MB: // most wifi interfaces pretend to be "ethernet"
        ret =  String::New("LINKTYPE_ETHERNET");
        break;
    case DLT_IEEE802_11: // I think this is for "monitor" mode
        ret = String::New("LINKTYPE_IEEE802_11");
        break;
    default:
        ret = String::New("Unknown");
        break;
    }
    return scope.Close(ret);
}

Handle<Value>
FindAllDevs(const Arguments& args)
{
    HandleScope scope;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp, *cur_dev;
    
    if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
        return ThrowException(Exception::TypeError(String::New(errbuf)));
    }

    Local<Array> DevsArray = Array::New();

    int i = 0;
    for (cur_dev = alldevsp ; cur_dev != NULL ; cur_dev = cur_dev->next, i++) {
        Local<Object> Dev = Object::New();

        Dev->Set(String::New("name"), String::New(cur_dev->name));
        if (cur_dev->description != NULL) {
            Dev->Set(String::New("description"), String::New(cur_dev->description));
        }
        Local<Array> AddrArray = Array::New();
        int j = 0;
        for (pcap_addr_t *cur_addr = cur_dev->addresses ; cur_addr != NULL ; cur_addr = cur_addr->next, j++) {
            if (cur_addr->addr->sa_family == AF_INET) {
                Local<Object> Address = Object::New();
                
                struct sockaddr_in *sin = (struct sockaddr_in *) cur_addr->addr;
                Address->Set(String::New("addr"), String::New(inet_ntoa(sin->sin_addr)));
                
                if (cur_addr->netmask != NULL) {
                    sin = (struct sockaddr_in *) cur_addr->netmask;
                    Address->Set(String::New("netmask"), String::New(inet_ntoa(sin->sin_addr)));
                }
                if (cur_addr->broadaddr != NULL) {
                    sin = (struct sockaddr_in *) cur_addr->broadaddr;
                    Address->Set(String::New("broadaddr"), String::New(inet_ntoa(sin->sin_addr)));
                }
                if (cur_addr->dstaddr != NULL) {
                    sin = (struct sockaddr_in *) cur_addr->dstaddr;
                    Address->Set(String::New("dstaddr"), String::New(inet_ntoa(sin->sin_addr)));
                }
                AddrArray->Set(Integer::New(j), Address);
            }
            // TODO - support AF_INET6
        }
        
        Dev->Set(String::New("addresses"), AddrArray);

        if (cur_dev->flags & PCAP_IF_LOOPBACK) {
            Dev->Set(String::New("flags"), String::New("PCAP_IF_LOOPBACK"));
        }

        DevsArray->Set(Integer::New(i), Dev);
    }

    pcap_freealldevs(alldevsp);
    return scope.Close(DevsArray);
}

Handle<Value>
Close(const Arguments& args)
{
    HandleScope scope;

    pcap_close(pcap_handle);

    return Undefined();
}

Handle<Value>
Fileno(const Arguments& args)
{
    HandleScope scope;

    int fd = pcap_get_selectable_fd(pcap_handle);

    return scope.Close(Integer::NewFromUnsigned(fd));
}

Handle<Value>
Stats(const Arguments& args)
{
    HandleScope scope;

    struct pcap_stat ps;

    if (pcap_stats(pcap_handle, &ps) == -1) {
        return ThrowException(Exception::Error(String::New("Error in pcap_stats")));
        // TODO - use pcap_geterr to figure out what the error was
    }

    Local<Object> stats_obj = Object::New();

    stats_obj->Set(String::New("ps_recv"), Integer::NewFromUnsigned(ps.ps_recv));
    stats_obj->Set(String::New("ps_drop"), Integer::NewFromUnsigned(ps.ps_drop));
    stats_obj->Set(String::New("ps_ifdrop"), Integer::NewFromUnsigned(ps.ps_ifdrop));
    // ps_ifdrop may not be supported on this platform, but there's no good way to tell
    
    return scope.Close(stats_obj);
}

Handle<Value>
DefaultDevice(const Arguments& args)
{
    HandleScope scope;
    
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        return ThrowException(Exception::Error(String::New(errbuf)));
    }

    return scope.Close(String::New(dev));
}

extern "C" void init (Handle<Object> target)
{
    HandleScope scope;

    target->Set(String::New("findalldevs"), FunctionTemplate::New(FindAllDevs)->GetFunction());
    target->Set(String::New("open_live"), FunctionTemplate::New(OpenLive)->GetFunction());
    target->Set(String::New("dispatch"), FunctionTemplate::New(Dispatch)->GetFunction());
    target->Set(String::New("fileno"), FunctionTemplate::New(Fileno)->GetFunction());
    target->Set(String::New("close"), FunctionTemplate::New(Close)->GetFunction());
    target->Set(String::New("stats"), FunctionTemplate::New(Stats)->GetFunction());
    target->Set(String::New("default_device"), FunctionTemplate::New(DefaultDevice)->GetFunction());
}
