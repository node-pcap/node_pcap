srcdir = "."
blddir = "build"
VERSION = "0.0.1"

def set_options(opt):
    opt.tool_options("compiler_cxx")

def configure(conf):
    conf.check_tool("compiler_cxx")
    conf.check_tool("node_addon")
    conf.check(lib="pcap", mandantory=True)

def build(bld):
    obj = bld.new_task_gen("cxx", "shlib", "node_addon")
    obj.target = "pcap_binding"
    obj.source = "pcap_binding.cc"
    obj.linkflags = ['-lpcap']
