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

char *default_device(void) {
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(NULL);
    }
    printf("Default device: %s\n", dev);
    return(dev);
}

struct bpf_program fp;              /* The compiled filter expression */
bpf_u_int32 mask;                   /* The netmask of our sniffing device */
bpf_u_int32 net;                    /* The IP of our sniffing device */
pcap_t *pcap_handle;
Buffer *buffer;

void packet_ready(u_char *callback_p, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    static int count = 1;
//    fprintf(stderr, "packet no: %d, %ld.%d, length: %d\n", count, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->len);
//    fflush(stderr);
    count++;

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

int open_live(char *dev, char *filter, char *errbuf) {
    // errbuf is on the stack of OpenLive

    fprintf(stderr, "open_live starting %s\n", dev);
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
        return(-1);
    }

    pcap_handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(-1);
    }

    if (pcap_setnonblock(pcap_handle, 1, errbuf) == -1) {
        fprintf(stderr, "Couldn't set nonblock: %s", errbuf);
        return(-1);
    }

    if (pcap_compile(pcap_handle, &fp, filter, 1, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(pcap_handle));
        return(-1);
    }

    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(pcap_handle));
        return(-1);
    }

    int fd = pcap_get_selectable_fd(pcap_handle);

#if defined(__APPLE_CC__) || defined(__APPLE__)
    #include <net/bpf.h>
    int v = 1;
    ioctl(fd, BIOCIMMEDIATE, &v);
    // TODO - check return value
#endif

    return (0);
}

Handle<Value>
    Dispatch(const Arguments& args)
{
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

    int packet_count = pcap_dispatch(pcap_handle, 1, packet_ready, (u_char *)&callback);

    return Integer::NewFromUnsigned(packet_count);
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
    if (open_live((char *) *device, (char *) *filter, errbuf) == -1) {
        return ThrowException(Exception::TypeError(String::New(errbuf)));
    }

    int link_type = pcap_datalink(pcap_handle);

    switch (link_type) {
    case DLT_NULL:
        return String::New("LINKTYPE_NULL");
    case DLT_EN10MB:
        return String::New("LINKTYPE_ETHERNET");
    case DLT_IEEE802_11:
        return String::New("LINKTYPE_IEEE802_11");
    default:
        return String::New("Unknown");
    }
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
    return DevsArray;
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

    return Integer::NewFromUnsigned(fd);
}

Handle<Value>
    Stats(const Arguments& args)
{
    HandleScope scope;

    struct pcap_stat ps;

    if (pcap_stats(pcap_handle, &ps) == -1) {
        return ThrowException(Exception::TypeError(String::New("Error in pcap_stats")));
        // TODO - use pcap_geterr to figure out what the error was
    }

    Local<Object> stats_obj = Object::New();

    stats_obj->Set(String::New("ps_recv"), Integer::NewFromUnsigned(ps.ps_recv));
    stats_obj->Set(String::New("ps_drop"), Integer::NewFromUnsigned(ps.ps_drop));
    stats_obj->Set(String::New("ps_ifdrop"), Integer::NewFromUnsigned(ps.ps_ifdrop));
    
    return stats_obj;
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
}
