---
title: Scan a network (CIDR)
description: Sweep a whole subnet for exposed back-end services — databases, Redis, Docker APIs, SSH — with scout scan --network.
---

`--network` sweeps an entire CIDR range for reachable **risky services**:
databases, Redis, Docker APIs, Elasticsearch, remote shells and the like. Scout
expands the range to its host addresses and connect-scans each one — a plain TCP
connect, no payloads — reporting every open service it finds across the network,
as a single graded scan.

```bash
scout scan --network 192.168.1.0/24
```

## Step 1 — find your network range

You need the CIDR of the network you are on. Find your own IP address and subnet
mask, then combine them into a range.

**Windows** (PowerShell or Command Prompt):

```powershell
ipconfig
```

Look under your active adapter (Wi-Fi or Ethernet) for **IPv4 Address** and
**Subnet Mask**, e.g. `192.168.1.37` with `255.255.255.0`.

**macOS:**

```bash
ipconfig getifaddr en0          # your IP (en0 = Wi-Fi, en1/en5 = Ethernet)
ifconfig en0 | grep netmask     # the mask, shown in hex (0xffffff00)
```

**Linux:**

```bash
ip -br addr        # shows the address with its prefix directly, e.g. 192.168.1.37/24
```

`ip addr` is easiest: it prints the prefix (`/24`) for you.

## Step 2 — turn it into a CIDR

Replace the last part of your IP with `0` and add the prefix for your mask:

| Subnet mask | Prefix | Your IP | Scan this range |
|---|---|---|---|
| `255.255.255.0` | `/24` | `192.168.1.37` | `192.168.1.0/24` (254 hosts — a typical home/office LAN) |
| `255.255.0.0` | `/16` | `10.0.5.9` | `10.0.0.0/16` (large; the maximum Scout allows) |
| `255.255.255.128` | `/25` | `192.168.1.200` | `192.168.1.128/25` |

Most home and small-office networks are a `/24` — if your IP is `192.168.1.37`,
the range is **`192.168.1.0/24`**. On Linux, `ip -br addr` already shows the
prefix, so `192.168.1.37/24` means you scan `192.168.1.0/24`.

## Step 3 — run the scan

```bash
scout scan --network 192.168.1.0/24
```

Repeat it for several ranges, and combine it with ordinary targets:

```bash
scout scan --network 10.0.0.0/24 --network 10.0.1.0/24
scout scan --target https://app.internal --network 10.0.0.0/24
```

## Authorization

:::danger
Only scan networks you **own or are explicitly authorized to test**. Your home
LAN is yours; a company or campus network needs written sign-off. Port-scanning a
network you do not control may be illegal.
:::

## What it finds

Each open service is a finding tagged with its host and port — for example:

```
[high]   Redis reachable on port 6379        192.168.1.40:6379
[critical] Docker API (plaintext) on 2375    192.168.1.12:2375
[medium] PostgreSQL reachable on port 5432   192.168.1.40:5432
```

The curated list covers Docker (2375/2376), Redis, MongoDB, Elasticsearch,
Memcached, PostgreSQL, MySQL, SQL Server, CouchDB, Telnet, RDP and SSH — back-end
services that should almost never be reachable across a network.

## Scope and limits

- **IPv4 ranges** up to a **/16** (65 534 hosts) per sweep; a larger prefix is
  refused — split it into smaller ranges. Network and broadcast addresses are
  skipped automatically.
- A laptop only sees what is **routable from where it sits**; a host behind a
  firewall or on another VLAN will look closed.
- It is a **connect scan** (safe mode): Scout opens a TCP connection and closes
  it. It sends no data and runs no exploit — it only observes whether the port
  accepts a connection.
- Results save to the same history and dashboard as any other scan, under a target
  named after the CIDR.
