#include <node.h>
#include <node_buffer.h>
#include <node_version.h>
#include <assert.h>
#include <pcap/pcap.h>
#include <v8.h>
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
using namespace node;

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
    Address->Set(String::New(key), String::New(address));
  }
}


void FindAllDevs(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *cur_dev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, errbuf)));
      return;
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
        for (pcap_addr_t *cur_addr = cur_dev->addresses ; cur_addr != NULL ; cur_addr = cur_addr->next, j++) {
          if (cur_addr->addr){
              int af = cur_addr->addr->sa_family;
              if(af == AF_INET || af == AF_INET6){
                Local<Object> Address = Object::New();
                SetAddrStringHelper("addr", cur_addr->addr, Address);
                SetAddrStringHelper("netmask", cur_addr->netmask, Address);
                SetAddrStringHelper("broadaddr", cur_addr->broadaddr, Address);
                SetAddrStringHelper("dstaddr", cur_addr->dstaddr, Address);
                AddrArray->Set(Integer::New(j), Address);
              }
           }
        }

        Dev->Set(String::New("addresses"), AddrArray);

        if (cur_dev->flags & PCAP_IF_LOOPBACK) {
            Dev->Set(String::New("flags"), String::New("PCAP_IF_LOOPBACK"));
        }

        DevsArray->Set(Integer::New(i), Dev);
    }

    pcap_freealldevs(alldevs);
    args.GetReturnValue().Set(DevsArray);
}

void DefaultDevice(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);
    char errbuf[PCAP_ERRBUF_SIZE];

    // Look up the first device with an address, pcap_lookupdev() just returns the first non-loopback device.
    pcap_if_t *alldevs, *dev;
    pcap_addr_t *addr;
    bool found = false;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
      isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, errbuf)));
      return;
    }

    if (alldevs == NULL) {
      isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate,"pcap_findalldevs didn't find any devs")));
      return;
    }

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if (dev->addresses != NULL && !(dev->flags & PCAP_IF_LOOPBACK)) {
            for (addr = dev->addresses; addr != NULL; addr = addr->next) {
                // TODO - include IPv6 addresses in DefaultDevice guess
                // if (addr->addr->sa_family == AF_INET || addr->addr->sa_family == AF_INET6) {
                if (addr->addr->sa_family == AF_INET) {
                    args.GetReturnValue().Set(String::NewFromUtf8(isolate, dev->name));
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
}

void LibVersion(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    args.GetReturnValue().Set(String::NewFromUtf8(isolate, pcap_lib_version()));
}

void Initialize(Handle<Object> exports)
{
//    HandleScope scope;

    PcapSession::Init(exports);

    exports->Set(String::New("findalldevs"), FunctionTemplate::New(FindAllDevs)->GetFunction());
    exports->Set(String::New("default_device"), FunctionTemplate::New(DefaultDevice)->GetFunction());
    exports->Set(String::New("lib_version"), FunctionTemplate::New(LibVersion)->GetFunction());
}

NODE_MODULE(pcap_binding, Initialize)
