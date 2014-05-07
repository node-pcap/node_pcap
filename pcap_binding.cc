#include <node.h>
#include <node_buffer.h>
#include <node_version.h>
#include <assert.h>
#include <v8.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <Ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

// Source: http://memset.wordpress.com/2010/10/09/inet_ntop-for-win32/
const char* inet_ntop(int af, const void* src, char* dst, int cnt){
 
    struct sockaddr_in srcaddr;
 
    memset(&srcaddr, 0, sizeof(struct sockaddr_in));
    memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));
 
    srcaddr.sin_family = af;
    if (WSAAddressToString((struct sockaddr*) &srcaddr, sizeof(struct sockaddr_in), 0, dst, (LPDWORD) &cnt) != 0) {
        DWORD rv = WSAGetLastError();
        return NULL;
    }
    return dst;
}

/*const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt)
{
    if (af == AF_INET)
    {
        struct sockaddr_in in;
        memset(&in, 0, sizeof(in));
        in.sin_family = AF_INET;
        memcpy(&in.sin_addr, src, sizeof(struct in_addr));
        getnameinfo((struct sockaddr *)&in, sizeof(struct
            sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
		printf("DST: %s\n",dst);
        return dst;
    }
    else if (af == AF_INET6)
    {
        struct sockaddr_in6 in;
        memset(&in, 0, sizeof(in));
        in.sin6_family = AF_INET6;
        memcpy(&in.sin6_addr, src, sizeof(struct in_addr6));
        getnameinfo((struct sockaddr *)&in, sizeof(struct
            sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
		printf("DST6: %s\n",dst);
        return dst;
    }
    return NULL;
}*/

#elif _linux_
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#endif

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
    } else {
      struct sockaddr_in6* saddr6 = (struct sockaddr_in6*) addr;
      src = (char*) &(saddr6->sin6_addr);
      size = INET6_ADDRSTRLEN;
    }
	
    const char* address = inet_ntop(addr->sa_family, src, dst_addr, size);
	if (address) {
		Address->Set(String::New(key), String::New(address));
	} else {
		Address->Set(String::New(key), String::New(""));
	}
  }
}

Handle<Value>
FindAllDevs(const Arguments& args)
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
    return scope.Close(DevsArray);
}

Handle<Value>
DefaultDevice(const Arguments& args)
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

void Initialize(Handle<Object> exports)
{
    HandleScope scope;

    PcapSession::Init(exports);

    exports->Set(String::New("findalldevs"), FunctionTemplate::New(FindAllDevs)->GetFunction());
    exports->Set(String::New("default_device"), FunctionTemplate::New(DefaultDevice)->GetFunction());
    exports->Set(String::New("lib_version"), FunctionTemplate::New(LibVersion)->GetFunction());
}

NODE_MODULE(pcap_binding, Initialize)
