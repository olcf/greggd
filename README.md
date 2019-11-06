# greggd

greg(g)d - Global runtime for eBPF-enabled gathering (w/ gumption) daemon

Intended to provide a way to daemonize eBPF queries and emit them to a socket for consumption.

## Sensors

Current eBPF and bcc tooling that "works" as a sensor:

  - opensnoop: file open() calls
  - biolatency: block I/O latency histograms
