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
    fprintf(stderr, "packet no: %d, %ld.%d, length: %d\n", count, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->len);
    fflush(stderr);
    count++;

    Local<Function> * callback = (Local<Function>*)callback_p;
    
    // TODO - bounds checking
    memcpy(buffer->data(), packet, pkthdr->caplen);

    TryCatch try_catch;

    Local<Object> packet_header = Object::New();

    double t = pkthdr->ts.tv_sec;
    t += (pkthdr->ts.tv_usec / 1000000);
    
    packet_header->Set(String::New("time"), Date::New(1000*t));
    packet_header->Set(String::New("caplen"), Integer::NewFromUnsigned(pkthdr->caplen));
    packet_header->Set(String::New("len"), Integer::NewFromUnsigned(pkthdr->len));
    
    Local<Value> argv[1] = { packet_header };

    (*callback)->Call(Context::GetCurrent()->Global(), 1, argv);

    if (try_catch.HasCaught())  {
        FatalException(try_catch);
    }
}

char *open_live(char *dev, char *filter) {
    char errbuf[PCAP_ERRBUF_SIZE];

    fprintf(stderr, "open_live starting %s\n", dev);
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
         fprintf(stderr, "Can't get netmask for device %s\n", dev);
         net = 0;
         mask = 0;
         return(NULL);
    }

    pcap_handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(NULL);
    }

    if (pcap_setnonblock(pcap_handle, 1, errbuf) == -1) {
        fprintf(stderr, "Couldn't set nonblock: %s", errbuf);
        return(NULL);
    }

    if (pcap_compile(pcap_handle, &fp, filter, 1, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(pcap_handle));
        return(NULL);
    }
    
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(pcap_handle));
        return(NULL);
    }

    int fd = pcap_get_selectable_fd(pcap_handle);

#if defined(__APPLE_CC__) || defined(__APPLE__)
    #include <net/bpf.h>
    int v = 1;
    ioctl(fd, BIOCIMMEDIATE, &v);
#endif

    // ev_io *pcap_watcher = (ev_io *) calloc(1, sizeof(ev_io));
    // 
    // ev_init(pcap_watcher, pcap_readable);
    // ev_io_set(pcap_watcher, fd, EV_READ);
    // ev_io_start(EV_DEFAULT_UC_ pcap_watcher);
    char *return_val = (char *) calloc(1, 10000);
    sprintf(return_val, "awesome: %d", fd);
    return (return_val);
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

    fprintf(stderr, "pcap_readable called\n");
    int packet_count = pcap_dispatch(pcap_handle, 1, packet_ready, (u_char *)&callback);
    fprintf(stderr, "pcap_dispatch returned %d\n", packet_count);

    return Integer::NewFromUnsigned(packet_count);
}

Handle<Value>
OpenLive(const Arguments& args)
{
  HandleScope scope;

  if (args.Length() != 2 || !args[0]->IsString() || !args[1]->IsString()) {
      return ThrowException(Exception::TypeError(String::New("Bad arguments")));
  }
  String::Utf8Value device(args[0]->ToString());
  String::Utf8Value filter(args[1]->ToString());
  char *str = open_live((char *) *device, (char *) *filter);
	     
  return String::New((const char*)str,strlen(str));
}

Handle<Value>
FindAllDevs(const Arguments& args)
{
  HandleScope scope;

//  int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
	     
  char str[] = "FindAllDevs not implemented yet";
  return String::New((const char*)str,strlen(str));
}

Handle<Value>
Close(const Arguments& args)
{
  HandleScope scope;

  char str[] = "Close not implemented yet";
	     
  return String::New((const char*)str,strlen(str));
}

Handle<Value>
Fileno(const Arguments& args)
{
  HandleScope scope;

  int fd = pcap_get_selectable_fd(pcap_handle);

  return Integer::NewFromUnsigned(fd);
}

extern "C" void init (Handle<Object> target)
{
  HandleScope scope;

  target->Set(String::New("findalldevs"), FunctionTemplate::New(FindAllDevs)->GetFunction());
  target->Set(String::New("open_live"), FunctionTemplate::New(OpenLive)->GetFunction());
  target->Set(String::New("dispatch"), FunctionTemplate::New(Dispatch)->GetFunction());
  target->Set(String::New("fileno"), FunctionTemplate::New(Fileno)->GetFunction());
  target->Set(String::New("close"), FunctionTemplate::New(Close)->GetFunction());
}
