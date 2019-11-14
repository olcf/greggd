# greggd

greg(g)d - Global runtime for eBPF-enabled gathering (w/ gumption) daemon

Intended to provide a way to daemonize eBPF queries and emit them to a socket for consumption.

## Sensors

Current eBPF and bcc tooling that "works" as a sensor:

  - opensnoop: file open() calls
  - biolatency: block I/O latency histograms

## Direction

Ideas for the current direction of this tool.

### 1.0

  * "Stable" tool
  * Ability to send metrics to socket
  * extendable/pluggable

### 2.0

  * Switch to Golang based agent

### 3.0

  * Switch to compiled byte code
  * Outside dependencies removed
  * Thorough build process for new kernels
