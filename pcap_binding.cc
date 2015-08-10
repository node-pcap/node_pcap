#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
#else
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#endif

#include <assert.h>
#include <pcap/pcap.h>
#include <iostream>
#include <stdio.h>

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
    Address->Set(NanNew(key), NanNew(address));
  }
}


NAN_METHOD(FindAllDevs)
{
    NanScope();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *cur_dev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
        NanThrowTypeError(errbuf);
        NanReturnUndefined();
    }

    Local<Array> DevsArray = NanNew<Array>();

    int i = 0;
    for (cur_dev = alldevs ; cur_dev != NULL ; cur_dev = cur_dev->next, i++) {
        Local<Object> Dev = NanNew<Object>();

        Dev->Set(NanNew("name"), NanNew(cur_dev->name));
        if (cur_dev->description != NULL) {
            Dev->Set(NanNew("description"), NanNew(cur_dev->description));
        }
        Local<Array> AddrArray = NanNew<Array>();
        int j = 0;
        for (pcap_addr_t *cur_addr = cur_dev->addresses ; cur_addr != NULL ; cur_addr = cur_addr->next, j++) {
          if (cur_addr->addr){
              int af = cur_addr->addr->sa_family;
              if(af == AF_INET || af == AF_INET6){
                Local<Object> Address = NanNew<Object>();
                SetAddrStringHelper("addr", cur_addr->addr, Address);
                SetAddrStringHelper("netmask", cur_addr->netmask, Address);
                SetAddrStringHelper("broadaddr", cur_addr->broadaddr, Address);
                SetAddrStringHelper("dstaddr", cur_addr->dstaddr, Address);
                AddrArray->Set(NanNew<Integer>(j), Address);
              }
           }
        }

        Dev->Set(NanNew("addresses"), AddrArray);

        if (cur_dev->flags & PCAP_IF_LOOPBACK) {
            Dev->Set(NanNew("flags"), NanNew("PCAP_IF_LOOPBACK"));
        }

        DevsArray->Set(NanNew<Integer>(i), Dev);
    }

    pcap_freealldevs(alldevs);
    NanReturnValue(DevsArray);
}

NAN_METHOD(DefaultDevice)
{
    NanScope();
    char errbuf[PCAP_ERRBUF_SIZE];

    // Look up the first device with an address, pcap_lookupdev() just returns the first non-loopback device.
    pcap_if_t *alldevs, *dev;
    pcap_addr_t *addr;
    bool found = false;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
      NanThrowError(errbuf);
      NanReturnUndefined();
    }

    if (alldevs == NULL) {
      NanThrowError("pcap_findalldevs didn't find any devs");
      NanReturnUndefined();
    }

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if (dev->addresses != NULL && !(dev->flags & PCAP_IF_LOOPBACK)) {
            for (addr = dev->addresses; addr != NULL; addr = addr->next) {
                // TODO - include IPv6 addresses in DefaultDevice guess
                // if (addr->addr->sa_family == AF_INET || addr->addr->sa_family == AF_INET6) {
                if (addr->addr->sa_family == AF_INET) {
                    NanReturnValue(NanNew(dev->name));
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
    NanReturnUndefined();
}

NAN_METHOD(LibVersion)
{
    NanScope();

    NanReturnValue(NanNew(pcap_lib_version()));
}

void Initialize(Handle<Object> exports)
{
//    HandleScope scope;

    PcapSession::Init(exports);

    exports->Set(NanNew("findalldevs"), NanNew<FunctionTemplate>(FindAllDevs)->GetFunction());
    exports->Set(NanNew("default_device"), NanNew<FunctionTemplate>(DefaultDevice)->GetFunction());
    exports->Set(NanNew("lib_version"), NanNew<FunctionTemplate>(LibVersion)->GetFunction());
}

NODE_MODULE(pcap_binding, Initialize)
