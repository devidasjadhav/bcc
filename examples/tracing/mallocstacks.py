#!/usr/bin/python
#
# mallocstacks  Trace malloc() calls in a process and print the full
#               stack trace for all callsites.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# This script is a basic example of the new Linux 4.6+ BPF_STACK_TRACE
# table API.
#
# Copyright 2016 GitHub, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep
import sys

if len(sys.argv) < 2:
    print("USAGE: mallocstacks PID [NUM_STACKS=1024]")
    exit()
pid = int(sys.argv[1])
if len(sys.argv) == 3:
    try:
        assert int(sys.argv[2]) > 0, ""
    except (ValueError, AssertionError) as e:
        print("USAGE: mallocstacks PID [NUM_STACKS=1024]")
        print("NUM_STACKS must be a non-zero, positive integer")
        exit()
    stacks = sys.argv[2]
else:
    stacks = "1024"

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>


BPF_STACK_TRACE(stack_traces, """ + stacks + """);
struct alloc_info_t {
    u32 size;
    int stack_id;
    u32 tid;
    };

BPF_PERF_OUTPUT(events);

int alloc_enter(struct pt_regs *ctx, size_t size) {
    u64 tgid_pid = bpf_get_current_pid_tgid();
    int key = stack_traces.get_stackid(ctx,
        BPF_F_USER_STACK|BPF_F_REUSE_STACKID);
    if (key < 0)
        return 0;
    u32 tid = tgid_pid >> 32;
    struct alloc_info_t info = {};
    info.size = size;
    info.stack_id = key;
    info.tid = tgid_pid >> 32;
    events.perf_submit(ctx, &info, sizeof(info));
    return 0;
    };
""")

def print_event(cpu, data, size):
    stack = []
    stack_traces = b.get_table("stack_traces")
    event = b["events"].event(data)
    tid = str(event.tid)
    size = str(event.size)
    print("malloc %s of size %s" % (tid,size))
    if event.stack_id > 0 :
        stack = stack_traces.walk(event.stack_id)
        for addr in stack:
            print("    %s" % b.sym(addr, pid))

b.attach_uprobe(name="c", sym="malloc", fn_name="alloc_enter", pid=pid)

print("Attaching to malloc in pid %d, Ctrl+C to quit." % pid)

b["events"].open_perf_buffer(print_event, page_cnt=64)

# poll until Ctrl-C
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
