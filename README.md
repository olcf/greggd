# greggd

greg(g)d - Global runtime for eBPF-enabled gathering (w/ gumption) daemon

Intended to provide a way to daemonize eBPF queries and emit them to a socket for consumption.

Compile and load eBPF programs into the kernel. Read binary stream out from
each program, parse it, and send output to a local socket on the host.

## Sensors

Current eBPF and bcc tooling that "works" as a sensor:

  - opensnoop: file open() calls
  - biolatency: block I/O latency histograms
  - tcplife: tcp session lifetime and connection details

## Config

The daemon needs to be aware of data format output by each program. The output
table needs to be looked up by the id, then the binary struct must be unpacked
into values. An example config for the `opensnoop` program is below.

```
  - source: /usr/share/greggd/c/opensnoop.c
    # Events to bind program to
    events:
      - type: kprobe
        loadFunc: trace_entry
        attachTo: do_sys_open
      - type: kretprobe
        loadFunc: trace_return
        attachTo: do_sys_open
    # What should we read from
    outputs:
      - type: BPF_PERF_OUTPUT
        id: opensnoop
        format:
          - name: id
            type: u64
          - name: pid
            type: u32
          - name: uid
            type: u32
          - name: ret
            type: int32
          - name: comm
            type: char[16]
          - name: fname
            type: char[255]
          - name: flag
            type: int32
```

A more complete full example can be found under `configs/config.yaml`.

## Roadmap

Ideas for the current direction of this tool.

### 1.0

  * "Stable" tool
  * Ability to send metrics to socket
  * extendable/pluggable

### 2.0

  * Switch to compiled byte code
  * Outside dependencies removed
  * Thorough build process for new kernels
