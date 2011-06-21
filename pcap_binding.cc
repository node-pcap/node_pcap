#include <node.h>
#include <node_events.h>
#include <node_buffer.h>
#include <node_version.h>
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

class Pcap: public EventEmitter {
    public:
        Pcap();
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;
        pcap_t *pcap_handle;
        char *buffer_data;
        size_t buffer_length;
        Local<Function> * callback;
        String * link_type;
        int fd;
        bool opened;


        // Exposed to v8
        static Handle<Value> New(const Arguments&);
        static Handle<Value> Open(bool, const Arguments &);
        static Handle<Value> OpenLive(const Arguments &);
        static Handle<Value> OpenOffline(const Arguments &);
        static Handle<Value> Close(const Arguments &);
        static Handle<Value> LinkType(const Arguments &);
        static Handle<Value> FileNo(const Arguments &);
        static Handle<Value> FindAllDevs(const Arguments &);
        static Handle<Value> Stats(const Arguments &);
        static Handle<Value> DefaultDevice(const Arguments &);
        static void Initialize(Handle<Object>);

        // non-v8
        void processPacket(const struct pcap_pkthdr*, const u_char*);
};


// PacketReady is called from within pcap, still on the stack of Dispatch.  It should be called
// only one time per Dispatch, but sometimes it gets called 0 times.  PacketReady invokes the
// callback stored in Pcap, which then invokes the JS callback associated with the dispatch()
// call in JS.
//
// Stack:
// 1. readWatcher.callback (pcap.js)
// 2. binding.dispatch (pcap.js)
// 3. Dispatch (binding.cc)
// 4. pcap_dispatch (libpcap)
// 5. PacketReady (binding.cc)
// 6. pcap->processPacket (binding.cc)
// 7. binding.dispatch callback (pcap.js)
//
void PacketReady(u_char *pcap_p, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    Pcap* pcap = (Pcap*) pcap_p;
    pcap->processPacket(pkthdr, packet);
}

void Pcap::processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    HandleScope scope;

    size_t copy_len = pkthdr->caplen;
    if (copy_len > buffer_length) {
        copy_len = buffer_length;
    }
    memcpy(buffer_data, packet, copy_len);

    TryCatch try_catch;

    Local<Object> packet_header = Object::New();

    packet_header->Set(String::New("tv_sec"), Integer::NewFromUnsigned(pkthdr->ts.tv_sec));
    packet_header->Set(String::New("tv_usec"), Integer::NewFromUnsigned(pkthdr->ts.tv_usec));
    packet_header->Set(String::New("caplen"), Integer::NewFromUnsigned(pkthdr->caplen));
    packet_header->Set(String::New("len"), Integer::NewFromUnsigned(pkthdr->len));

    Local<Value> argv[1] = packet_header;

    (*callback)->Call(Context::GetCurrent()->Global(), 1, argv);

    if (try_catch.HasCaught())  {
        FatalException(try_catch);
    }
}

Handle<Value>
Dispatch(const Arguments& args)
{
    HandleScope scope;

    Pcap* pcap = ObjectWrap::Unwrap<Pcap>(args.This());

    if (args.Length() != 2) {
        return ThrowException(Exception::TypeError(String::New("Dispatch takes exactly two arguments")));
    }

    if (!Buffer::HasInstance(args[0])) {
        return ThrowException(Exception::TypeError(String::New("First argument must be a buffer")));
    }

    if (!args[1]->IsFunction()) {
        return ThrowException(Exception::TypeError(String::New("Second argument must be a function")));
    }

#if NODE_VERSION_AT_LEAST(0,3,0)
    Local<Object> buffer_obj = args[0]->ToObject();
    pcap->buffer_data = Buffer::Data(buffer_obj);
    pcap->buffer_length = Buffer::Length(buffer_obj);
#else
    Buffer *buffer_obj = ObjectWrap::Unwrap<Buffer>(args[0]->ToObject());
    pcap->buffer_data = buffer_obj->data();
    pcap->buffer_length = buffer_obj->length();
#endif

    Local<Function> callback = Local<Function>::Cast(args[1]);
    pcap->callback = &callback;

    int packet_count, total_packets = 0;
    do {
        packet_count = pcap_dispatch(pcap->pcap_handle, 1, PacketReady, (u_char *)pcap);
        if (packet_count < 0) {
            return ThrowException(Exception::Error(String::New(pcap_geterr(pcap->pcap_handle))));
        }
        total_packets += packet_count;
    } while (packet_count > 0 && pcap->opened);

    return scope.Close(Integer::NewFromUnsigned(total_packets));
}

Pcap::Pcap(): EventEmitter() {
    opened = false;
    fd = NULL;
}

Handle<Value> Pcap::New(const Arguments& args) {
    HandleScope scope;
    Pcap * pcap = new Pcap();

    if (pcap == NULL) {
        return ThrowException(Exception::TypeError(String::New("pcap New: out of memory")));
    }

    pcap->Wrap(args.This());
    return args.This();
}

Handle<Value>
Pcap::Open(bool live, const Arguments& args)
{
        HandleScope scope;
        char errbuf[PCAP_ERRBUF_SIZE];
        Pcap* pcap = ObjectWrap::Unwrap<Pcap>(args.This());

        if (pcap == NULL) {
            return ThrowException(Exception::TypeError(String::New("pcap Open: out of memory")));
        }

        if (args.Length() == 3) { 
            if (!args[0]->IsString()) {
                return ThrowException(Exception::TypeError(String::New("pcap Open: args[0] must be a String")));
            }
            if (!args[1]->IsString()) {
                return ThrowException(Exception::TypeError(String::New("pcap Open: args[1] must be a String")));
            }
            if (!args[2]->IsInt32()) {
                return ThrowException(Exception::TypeError(String::New("pcap Open: args[2] must be a Number")));
            }
        } else {
            return ThrowException(Exception::TypeError(String::New("pcap Open: expecting 3 arguments")));
        }
        String::Utf8Value device(args[0]->ToString());
        String::Utf8Value filter(args[1]->ToString());
        int buffer_size = args[2]->Int32Value();

        if (live) {
            if (pcap_lookupnet((char *) *device, &(pcap->net), &(pcap->mask), errbuf) == -1) {
                pcap->net = 0;
                pcap->mask = 0;
                fprintf(stderr, "warning: %s - this may not actually work\n", errbuf);
            }

            pcap->pcap_handle = pcap_create((char *) *device, errbuf);
            if (pcap->pcap_handle == NULL) {
                return ThrowException(Exception::Error(String::New(errbuf)));
            }

            // 64KB is the max IPv4 packet size
            if (pcap_set_snaplen(pcap->pcap_handle, 65535) != 0) {
                return ThrowException(Exception::Error(String::New("error setting snaplen")));
            }

            // always use promiscuous mode
            if (pcap_set_promisc(pcap->pcap_handle, 1) != 0) {
                return ThrowException(Exception::Error(String::New("error setting promiscuous mode")));
            }

            // Try to set buffer size.  Sometimes the OS has a lower limit that it will silently enforce.
            if (pcap_set_buffer_size(pcap->pcap_handle, buffer_size) != 0) {
                return ThrowException(Exception::Error(String::New("error setting buffer size")));
            }

            // set "timeout" on read, even though we are also setting nonblock below.  On Linux this is required.
            if (pcap_set_timeout(pcap->pcap_handle, 1000) != 0) {
                return ThrowException(Exception::Error(String::New("error setting read timeout")));
            }

            // TODO - pass in an option to enable rfmon on supported interfaces.  Sadly, it can be a disruptive
            // operation, so we can't just always try to turn it on.
            // if (pcap_set_rfmon(pcap->pcap_handle, 1) != 0) {
            //     return ThrowException(Exception::Error(String::New(pcap_geterr(pcap->pcap_handle))));
            // }

            if (pcap_activate(pcap->pcap_handle) != 0) {
                return ThrowException(Exception::Error(String::New(pcap_geterr(pcap->pcap_handle))));
            }
        } else {
            // Device is the path to the savefile
            pcap->pcap_handle = pcap_open_offline((char *) *device, errbuf);
            if (pcap->pcap_handle == NULL) {
                return ThrowException(Exception::Error(String::New(errbuf)));
            }
        }

        if (pcap_setnonblock(pcap->pcap_handle, 1, errbuf) == -1) {
            return ThrowException(Exception::Error(String::New(errbuf)));
        }

        // TODO - if filter is empty, don't bother with compile or set
        if (pcap_compile(pcap->pcap_handle, &(pcap->fp), (char *) *filter, 1, pcap->net) == -1) {
            return ThrowException(Exception::Error(String::New(pcap_geterr(pcap->pcap_handle))));
        }

        if (pcap_setfilter(pcap->pcap_handle, &(pcap->fp)) == -1) {
            return ThrowException(Exception::Error(String::New(pcap_geterr(pcap->pcap_handle))));
        }

        // Work around buffering bug in BPF on OSX 10.6 as of May 19, 2010
        // This may result in dropped packets under load because it disables the (broken) buffer
        // http://seclists.org/tcpdump/2010/q1/110
#if defined(__APPLE_CC__) || defined(__APPLE__)
        #include <net/bpf.h>
        if (live) {
            int fd = pcap_get_selectable_fd(pcap->pcap_handle);
            int v = 1;
            if (ioctl(fd, BIOCIMMEDIATE, &v) == -1) {
                return ThrowException(Exception::Error(String::New("error setting BIOCIMMEDIATE")));
            }
        }
#endif
        return Undefined();
}

Handle<Value>
Pcap::OpenLive(const Arguments& args)
{
    return Open(true, args);
}

Handle<Value>
Pcap::OpenOffline(const Arguments& args)
{
    return Open(false, args);
}

Handle<Value>
Pcap::FindAllDevs(const Arguments& args)
{
    HandleScope scope;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *cur_dev;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
        return ThrowException(Exception::TypeError(String::New(errbuf)));
    }

    Local<Array> DevsArray = Array::New();

    int i = 0;
    for (cur_dev = alldevs ; cur_dev != NULL ; cur_dev = cur_dev->next, i++) {
        Local<Object> Dev = Object::New();

        Dev->Set(String::New("name"), String::New(cur_dev->name));
        if (cur_dev->description != NULL) {
            Dev->Set(String::New("description"), String::New(cur_dev->description));
        }
        Local<Array> AddrArray = Array::New();
        int j = 0;
        for (pcap_addr_t *cur_addr = cur_dev->addresses ; cur_addr != NULL ; cur_addr = cur_addr->next) {
            if (cur_addr->addr && cur_addr->addr->sa_family == AF_INET) {
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
                j++;
            }
            // TODO - support AF_INET6
        }
        
        Dev->Set(String::New("addresses"), AddrArray);

        if (cur_dev->flags & PCAP_IF_LOOPBACK) {
            Dev->Set(String::New("flags"), String::New("PCAP_IF_LOOPBACK"));
        }

        DevsArray->Set(Integer::New(i), Dev);
    }

    pcap_freealldevs(alldevs);
    return scope.Close(DevsArray);
}

Handle<Value>
Pcap::Close(const Arguments& args)
{
    HandleScope scope;
    Pcap* pcap = ObjectWrap::Unwrap<Pcap>(args.This());

    pcap_close(pcap->pcap_handle);
    pcap->opened = false;

    return Undefined();
}

Handle<Value>
Pcap::FileNo(const Arguments& args)
{
    HandleScope scope;
    Pcap* pcap = ObjectWrap::Unwrap<Pcap>(args.This());

    int fd = pcap_get_selectable_fd(pcap->pcap_handle);

    return scope.Close(Integer::NewFromUnsigned(fd));
}

Handle<Value>
Pcap::Stats(const Arguments& args)
{
    HandleScope scope;
    Pcap* pcap = ObjectWrap::Unwrap<Pcap>(args.This());

    struct pcap_stat ps;

    if (pcap_stats(pcap->pcap_handle, &ps) == -1) {
        return ThrowException(Exception::Error(String::New(pcap_geterr(pcap->pcap_handle))));
    }

    Local<Object> stats_obj = Object::New();

    stats_obj->Set(String::New("ps_recv"), Integer::NewFromUnsigned(ps.ps_recv));
    stats_obj->Set(String::New("ps_drop"), Integer::NewFromUnsigned(ps.ps_drop));
    stats_obj->Set(String::New("ps_ifdrop"), Integer::NewFromUnsigned(ps.ps_ifdrop));
    // ps_ifdrop may not be supported on this platform, but there's no good way to tell, is there?
    
    return scope.Close(stats_obj);
}


Handle<Value>
Pcap::LinkType(const Arguments& args)
{
    HandleScope scope;
    char errbuf[PCAP_ERRBUF_SIZE];
    Pcap* pcap = ObjectWrap::Unwrap<Pcap>(args.This());

    int link_type = pcap_datalink(pcap->pcap_handle);

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
    default:
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unknown linktype %d", link_type);
        ret = String::New(errbuf);
        break;
    }
    return scope.Close(ret);
}

Handle<Value>
Pcap::DefaultDevice(const Arguments& args)
{
    HandleScope scope;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Look up the first device with an address, pcap_lookupdev() just returns the first non-loopback device.
    Local<Value> ret;
    pcap_if_t *alldevs, *dev;
    pcap_addr_t *addr;
    bool found = false;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
        return ThrowException(Exception::Error(String::New(errbuf)));
    }

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if (dev->addresses != NULL && !(dev->flags & PCAP_IF_LOOPBACK)) {
            for (addr = dev->addresses; addr != NULL; addr = addr->next) {
                // TODO - include IPv6 addresses in DefaultDevice guess
                // if (addr->addr->sa_family == AF_INET || addr->addr->sa_family == AF_INET6) {
                if (addr->addr->sa_family == AF_INET) {
                    ret = String::New(dev->name);
                    found = true;
                    break;
                }
            }

            if (found) {
                break;
            }
        }
    }

    pcap_freealldevs(alldevs);
    return scope.Close(ret);
}

Handle<Value>
LibVersion(const Arguments &args)
{
    HandleScope scope;

    return scope.Close(String::New(pcap_lib_version()));
}

void Pcap::Initialize(Handle<Object> target) {
    Local<FunctionTemplate> t = FunctionTemplate::New(New);
    t->Inherit(EventEmitter::constructor_template);
    t->InstanceTemplate()->SetInternalFieldCount(1);

    // Class methods
    NODE_SET_PROTOTYPE_METHOD(t, "findalldevs", FindAllDevs);
    NODE_SET_PROTOTYPE_METHOD(t, "open_live", OpenLive);
    NODE_SET_PROTOTYPE_METHOD(t, "open_offline", OpenOffline);
    NODE_SET_PROTOTYPE_METHOD(t, "dispatch", Dispatch);
    NODE_SET_PROTOTYPE_METHOD(t, "fileno", FileNo);
    NODE_SET_PROTOTYPE_METHOD(t, "link_type", LinkType);
    NODE_SET_PROTOTYPE_METHOD(t, "_close", Close);
    NODE_SET_PROTOTYPE_METHOD(t, "stats", Stats);
    NODE_SET_PROTOTYPE_METHOD(t, "default_device", DefaultDevice);

    // Static functions
    target->Set(String::New("lib_version"), FunctionTemplate::New(LibVersion)->GetFunction());
    target->Set(v8::String::NewSymbol("Pcap"), t->GetFunction());
}

extern "C" void init (Handle<Object> target)
{
    HandleScope scope;
    Pcap::Initialize(target);
}
