#include <assert.h>
#include <pcap/pcap.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "pcap_session.h"

using namespace v8;
using Nan::Callback;
using Nan::AsyncQueueWorker;
using Nan::AsyncWorker;
using Nan::Callback;
using Nan::HandleScope;
using Nan::New;
using Nan::Null;
using Nan::To;

class PcapWorker : public AsyncWorker {
 public:
  PcapWorker(
        Callback *callback,
        std::string device,
        std::string filter,
        int buffer_size,
        std::string pcap_output_filename,
        int num_packets
    )
    : 
    AsyncWorker(callback), 
    device(device), 
    filter(filter),
    buffer_size(buffer_size),
    pcap_output_filename(pcap_output_filename),
    num_packets(num_packets)
    {}
  ~PcapWorker() {}

  // Executed inside the worker-thread.
  // It is not safe to access V8, or V8 data structures
  // here, so everything we need for input and output
  // should go on `this`.
  void Execute () {
    if (pcap_lookupnet(device.c_str(), &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
        fprintf(stderr, "warning: %s - this may not actually work\n", errbuf);
        SetErrorMessage(errbuf);
        return;
    }
    pcap_handle = pcap_create(device.c_str(), errbuf);
    if (pcap_handle == NULL) {
        SetErrorMessage(errbuf);
        return;
    }
     
    // 64KB is the max IPv4 packet size
    if (pcap_set_snaplen(pcap_handle, 65535) != 0) {
       SetErrorMessage("error setting snaplen");
        return;
    }

    // always use promiscuous mode
    if (pcap_set_promisc(pcap_handle, 1) != 0) {
        SetErrorMessage("error setting promiscuous mode");
        return;
    }
    
    // Try to set buffer size.  Sometimes the OS has a lower limit that it will silently enforce.
    if (pcap_set_buffer_size(pcap_handle, buffer_size) != 0) {
        SetErrorMessage("error setting buffer size");
        return;
    }
      
    
    // set "timeout" on read, even though we are also setting nonblock below.  On Linux this is required.
    if (pcap_set_timeout(pcap_handle, 1000) != 0) {
        SetErrorMessage("error setting read timeout");
        return;
    }
    
    if (pcap_activate(pcap_handle) != 0) {
        SetErrorMessage(pcap_geterr(pcap_handle));
        return;
    }
    if ((pcap_output_filename.size()) > 0) {
        pcap_dump_handle = pcap_dump_open(pcap_handle,pcap_output_filename.c_str());
        if (pcap_dump_handle == NULL) {
            SetErrorMessage("error opening dump");
            return;
        }
    }
    
    
    if (filter.size() != 0) {
        if (pcap_compile(pcap_handle, &fp, filter.c_str(), 1, net) == -1) {
            SetErrorMessage(pcap_geterr(pcap_handle));
            return;
        }
           
        if (pcap_setfilter(pcap_handle, &fp) == -1) {
            SetErrorMessage(pcap_geterr(pcap_handle));
            return;
        }

        pcap_loop(pcap_handle, num_packets, OnPacketReady, (unsigned char *)pcap_dump_handle);
        pcap_freecode(&fp);
        /*
         * Close the savefile opened in pcap_dump_open().
         */
        pcap_dump_close(pcap_dump_handle);
        /*
         * Close the packet capture device and free the memory used by the
         * packet capture descriptor.
         */     
        pcap_close(pcap_handle);
    }
  }

  // Executed when the async work is complete
  // this function will be run inside the main event loop
  // so it is safe to use V8 again
  void HandleOKCallback () {

    Nan::HandleScope scope;

    Local<Value> argv[] = {
        Nan::Null()
      , New<Number>(num_packets)
    };

    callback->Call(2, argv);
  }



static void OnPacketReady(u_char *s, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
   pcap_dump(s, pkthdr, packet);
}

 private:

    std::string device;
    std::string filter;
    int buffer_size;
    std::string pcap_output_filename;
    int num_packets;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t *pcap_handle;
    pcap_dumper_t *pcap_dump_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
  

   
  
};


// Helper method, convert a sockaddr* (AF_INET or AF_INET6) to a string, and set it as the property
// named 'key' in the Address object you pass in.
void SetAddrStringHelper(const char* key, sockaddr *addr, Local<Object> Address){
  if(key && addr){
    char dst_addr[INET6_ADDRSTRLEN + 1] = {0};
    char* src = 0;
    socklen_t size = 0;
    if(addr->sa_family == AF_INET){
      struct sockaddr_in* saddr = (struct sockaddr_in*) addr;
      src = (char*) &(saddr->sin_addr);
      size = INET_ADDRSTRLEN;
    }else{
      struct sockaddr_in6* saddr6 = (struct sockaddr_in6*) addr;
      src = (char*) &(saddr6->sin6_addr);
      size = INET6_ADDRSTRLEN;
    }
    const char* address = inet_ntop(addr->sa_family, src, dst_addr, size);
    if(address){
        Address->Set(Nan::New(key).ToLocalChecked(), Nan::New(address).ToLocalChecked());
    }
  }
}


NAN_METHOD(FindAllDevs)
{
    Nan::HandleScope scope;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *cur_dev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
        Nan::ThrowTypeError(errbuf);
        return;
    }

    Local<Array> DevsArray = Nan::New<Array>();

    int i = 0;
    for (cur_dev = alldevs ; cur_dev != NULL ; cur_dev = cur_dev->next, i++) {
        Local<Object> Dev = Nan::New<Object>();

        Dev->Set(Nan::New("name").ToLocalChecked(), Nan::New(cur_dev->name).ToLocalChecked());
        if (cur_dev->description != NULL) {
            Dev->Set(Nan::New("description").ToLocalChecked(), Nan::New(cur_dev->description).ToLocalChecked());
        }
        Local<Array> AddrArray = Nan::New<Array>();
        int j = 0;
        for (pcap_addr_t *cur_addr = cur_dev->addresses ; cur_addr != NULL ; cur_addr = cur_addr->next, j++) {
          if (cur_addr->addr){
              int af = cur_addr->addr->sa_family;
              if(af == AF_INET || af == AF_INET6){
                Local<Object> Address = Nan::New<Object>();
                SetAddrStringHelper("addr", cur_addr->addr, Address);
                SetAddrStringHelper("netmask", cur_addr->netmask, Address);
                SetAddrStringHelper("broadaddr", cur_addr->broadaddr, Address);
                SetAddrStringHelper("dstaddr", cur_addr->dstaddr, Address);
                AddrArray->Set(Nan::New<Integer>(j), Address);
              }
           }
        }

        Dev->Set(Nan::New("addresses").ToLocalChecked(), AddrArray);

        if (cur_dev->flags & PCAP_IF_LOOPBACK) {
            Dev->Set(Nan::New("flags").ToLocalChecked(), Nan::New("PCAP_IF_LOOPBACK").ToLocalChecked());
        }

        DevsArray->Set(Nan::New<Integer>(i), Dev);
    }

    pcap_freealldevs(alldevs);
    info.GetReturnValue().Set(DevsArray);
}

NAN_METHOD(DefaultDevice)
{
    Nan::HandleScope scope;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Look up the first device with an address, pcap_lookupdev() just returns the first non-loopback device.
    pcap_if_t *alldevs, *dev;
    pcap_addr_t *addr;
    bool found = false;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
      Nan::ThrowError(errbuf);
      return;
    }

    if (alldevs == NULL) {
      Nan::ThrowError("pcap_findalldevs didn't find any devs");
      return;
    }

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if (dev->addresses != NULL && !(dev->flags & PCAP_IF_LOOPBACK)) {
            for (addr = dev->addresses; addr != NULL; addr = addr->next) {
                // TODO - include IPv6 addresses in DefaultDevice guess
                // if (addr->addr->sa_family == AF_INET || addr->addr->sa_family == AF_INET6) {
                if (addr->addr->sa_family == AF_INET) {
                    info.GetReturnValue().Set(Nan::New(dev->name).ToLocalChecked());
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
    return;
}

NAN_METHOD(LibVersion)
{
    info.GetReturnValue().Set(Nan::New(pcap_lib_version()).ToLocalChecked());
}

// Asynchronous access to the `Estimate()` function
NAN_METHOD(PcapDumpAsync) {

    if (info.Length() == 8) {
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
        if (!info[6]->IsInt32()) {
            Nan::ThrowTypeError("pcap Open: info[6] must be a Number");
            return;
        }
        if (!info[7]->IsFunction()) {
            Nan::ThrowTypeError("pcap Open: info[7] must be a Function");
            return;
        }
    } else {
        Nan::ThrowTypeError("pcap CreatePcapDump: expecting 7 arguments");
        return;
    }
    Nan::Utf8String device(info[0]->ToString());
    Nan::Utf8String filter(info[1]->ToString());
    int buffer_size = info[2]->Int32Value();
    Nan::Utf8String pcap_output_filename(info[3]->ToString());
    int num_packets = info[6]->Int32Value();
    Callback *callback = new Callback(info[7].As<Function>()); 

  AsyncQueueWorker(new PcapWorker(callback, std::string(*device),std::string(*filter),buffer_size, std::string(*pcap_output_filename),num_packets));
}


void Initialize(Handle<Object> exports)
{
    Nan::HandleScope scope;

    PcapSession::Init(exports);

    exports->Set(Nan::New("findalldevs").ToLocalChecked(), Nan::New<FunctionTemplate>(FindAllDevs)->GetFunction());
    exports->Set(Nan::New("default_device").ToLocalChecked(), Nan::New<FunctionTemplate>(DefaultDevice)->GetFunction());
    exports->Set(Nan::New("lib_version").ToLocalChecked(), Nan::New<FunctionTemplate>(LibVersion)->GetFunction());
    exports->Set(Nan::New("create_pcap_dump_async").ToLocalChecked(), Nan::New<FunctionTemplate>(PcapDumpAsync)->GetFunction());
}

NODE_MODULE(pcap_binding, Initialize)
