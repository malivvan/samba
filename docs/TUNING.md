# Tuning for high-speed links

The server itself rarely needs tuning; the link and the client usually do. What
follows is ordered by how often it is the actual bottleneck.

## 1. Spread the load across cores (multichannel)

One TCP connection is served by one driver goroutine, so a single stream tops
out well below a fast NIC. The scaling axis is **connections**, and SMB3
multichannel makes one mount use several:

```toml
# server
multichannel = true
# advertise only the storage NIC if the host has several
advertise_only = ["10.99.0.10"]
```

```sh
# client
mount -t cifs //server/data /mnt -o username=...,vers=3.1.1,multichannel,max_channels=8
```

The server advertises its interfaces (with link speed and RSS capability)
through `FSCTL_QUERY_NETWORK_INTERFACE_INFO`; the client decides how many
channels to open from that. Each channel lands on a different worker because
every worker has its own `SO_REUSEPORT` listener (on a platform without that
option — Windows — the workers share one socket instead, and the difference is
only who balances the accepts; see the README support table).

Note the interaction with signing: a signed channel takes the buffered read
path, so signed multichannel throughput is bounded by AES-CMAC, not by the
network. Use guest or unsigned traffic for maximum read throughput. The same
applies to the platform itself: on Windows a large read is copied through
userspace, so the throughput numbers in `docs/BENCHMARKS.md` (measured on Linux
with `splice(2)`) are not what a Windows server will do.

## 2. Check the raw link first

Before blaming the server, measure what the link can do:

```sh
# raw TCP ceiling between the two hosts, same path and MTU
bench/net-iperf.sh <server-ip>
```

A single-queue virtio NIC at MTU 1500 caps around 9 Gbps no matter how many
streams you run, while the same hardware with multiqueue and jumbo frames
reaches ~80 Gbps. If iperf and SMB scale the same way, the server is not the
limit.

## 3. Jumbo frames

MTU is an OS/NIC setting, not an application one, and it mostly helps by
sending fewer packets and interrupts per byte. It is worth doing on dedicated
storage networks:

```sh
ip link set dev eth0 mtu 9000      # both ends, plus the switch/fabric
```

The server already advertises `CAP_LARGE_MTU`, asks for 1 MiB reads and 4 MiB
writes, and disables Nagle on accepted sockets.

## 4. Kernel and socket buffers

For high bandwidth-delay-product links, the send and receive buffers on the
server's sockets may need to be raised (the server does not set them
explicitly):

```sh
sysctl -w net.core.rmem_max=134217728 net.core.wmem_max=134217728
sysctl -w net.ipv4.tcp_rmem='4096 87380 134217728'
sysctl -w net.ipv4.tcp_wmem='4096 65536 134217728'
```

## 5. Client-side settings

- **Do not use `cache=none`.** It disables readahead, so a channel can never
  fill. If you need a cold measurement, drop the page cache
  (`echo 3 > /proc/sys/vm/drop_caches`) and read distinct files per stream.
- Raise `rsize`/`wsize` only if the client is not already asking for the
  advertised maxima; the server caps reads at 1 MiB on purpose (see
  [BENCHMARKS.md](BENCHMARKS.md)).
- Increase `max_channels` until throughput stops scaling.

## 6. Encrypted and signed traffic

Encryption and signing both force the read payload through userspace, so they
change the bottleneck from the network to the CPU:

- prefer AES-GCM over AES-CCM (roughly 9× faster in this port; see
  [BENCHMARKS.md](BENCHMARKS.md)),
- leave `prefer_aes256 = false` unless policy requires 256-bit keys — AES-128-GCM
  is faster on most CPUs and both are accepted,
- scale out with multichannel, which now spreads the cipher work across cores.

## 7. Worker count

`workers = 0` (one listener per CPU) is right for almost every deployment. Set a
lower value if you want to reserve cores for other work; set it higher only if
you have more NIC queues than cores. If `workers` exceeds the number of physical
cores, expect less, not more.
