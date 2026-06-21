# `full-configured` — lego against an internal step-ca over DNS-01

This scenario stands up a complete, self-contained ACME lab in a single
container:

* **PowerDNS** (authoritative) serving the `lab.local` zone
* **step-ca** as an internal ACME CA
* **lego** + `lego-renew.py`, issuing certificates for `*.lab.local` via the
  **DNS-01** challenge

Getting DNS-01 to work against an *internal* CA with an *internal* DNS server
on *non-standard ports* hides a surprising number of traps. This document
records each one — symptom, root cause, fix — so you don't rediscover them.

> TL;DR: there are **two independent DNS consumers** with **different
> resolution paths**, and an internal CA needs its **trust anchor** handed to
> lego explicitly. Miss either and you get cryptic errors far from the cause.

---

## The two DNS consumers (this is the key insight)

DNS-01 validation involves DNS lookups from **two different programs**, and
they do **not** share a resolver:

| Consumer | Role | How it resolves DNS |
|----------|------|---------------------|
| **lego** (the ACME *client*) | Writes the `_acme-challenge` TXT record via the PowerDNS API, then runs a self-check before telling the CA to validate | Uses whatever you pass via `--dns.resolvers`; **ignores** `/etc/resolv.conf` if that flag is set |
| **step-ca** (the ACME *server*) | Independently looks up the `_acme-challenge` TXT record to validate the challenge | Uses the **system resolver** (`/etc/resolv.conf`) — there is **no** override flag |

Pointing lego at PowerDNS is necessary but **not sufficient**: step-ca still
has to find the record through the system resolver. Fixing only the lego side
gets you all the way to `The server validated our request` failing silently
or the order never completing.

---

## Ports & addresses in this lab

| Service | Address | Port | Protocol | Notes |
|---------|---------|------|----------|-------|
| step-ca ACME directory | `ca.lab.local` | **9000** | HTTPS | self-signed chain |
| PowerDNS authoritative | `127.0.0.1` | **5300** | DNS | **not** 53! |
| PowerDNS API / webserver | `dns.lab.local` | **8081** | **HTTP** | **not** HTTPS! |
| dnsmasq (split forwarder) | `10.31.0.1` | 53 | DNS | added in `prepare` |
| Docker embedded DNS | `127.0.0.11` | 53 | DNS | the container's `resolv.conf` |
| Container IP (lego network) | `10.31.0.1` | — | — | from `molecule.yml` |

`ca.lab.local`, `dns.lab.local`, etc. resolve via **`/etc/hosts`** (Docker
`etc_hosts:` in `molecule.yml`), *not* via DNS. That is why the CA and API
connections work even though the system resolver knows nothing about
`lab.local`.

---

## The full DNS resolution chain

```
                         ┌─────────────────────────────────────────────┐
 step-ca / apt / curl ──▶│ /etc/resolv.conf  →  127.0.0.11 (Docker DNS) │
                         └───────────────┬─────────────────────────────┘
                                         │ forwards non-container queries to
                                         │ dns_servers (set in molecule.yml):
                                         ▼
                       ┌───────────────────────────────┐
                       │ 1. 10.31.0.1  →  dnsmasq       │
                       │ 2. 1.1.1.1    →  bootstrap only│ (while dnsmasq installs)
                       └───────────────┬───────────────┘
                                       │
                 ┌─────────────────────┴───────────────────────┐
                 ▼                                              ▼
   lab.local  →  127.0.0.1:5300 (PowerDNS auth)    everything else  →  1.1.1.1

 lego (client) bypasses all of the above and talks to PowerDNS directly:
   lego  ──(--dns.resolvers 127.0.0.1:5300)──▶  PowerDNS auth
```

---

## Painpoints

### 1. `x509: certificate signed by unknown authority`

**When:** the very first `lego ... run` against the CA.
**Cause:** lego does not trust step-ca's self-signed root.
**Fix:** publish the root and point the issuer at it.

* step-ca writes its root to `/opt/step-ca/.step/certs/root_ca.crt`
  (readable only by the `step-ca` user).
* `prepare.yml` copies it to `/etc/ssl/lab-root.crt` (world-readable).
* The issuer sets `ca_certificate: /etc/ssl/lab-root.crt`; `lego-renew.py`
  exports it as `LEGO_CA_CERTIFICATES` for the lego subprocess.

> A manual `lego` invocation will fail here unless you export
> `LEGO_CA_CERTIFICATES=/etc/ssl/lab-root.crt` yourself — `lego-renew.py`
> does it for you.
>
> Run `lego-renew.py --preflight` to validate the trust anchor (and probe the
> ACME endpoint over TLS) *before* a real issuance.

### 2. `http: server gave HTTP response to HTTPS client`

**When:** lego's pdns provider calls the PowerDNS API.
**Cause:** the PowerDNS API webserver speaks **plain HTTP**; the issuer's
`PDNS_API_URL` used `https://`.
**Fix:** `PDNS_API_URL: "http://dns.lab.local:8081"`.

### 3. `pdns: could not find zone for domain "lab.local" ... NXDOMAIN`

**When:** lego tries to determine the zone apex for the TXT record.
**Cause:** lego's zone detection (`FindZoneByFqdn`) does an SOA lookup via
the **system resolver**, which cannot reach PowerDNS on the non-standard
port 5300.
**Fix:** give lego an explicit resolver — `challenge.resolvers: ["127.0.0.1:5300"]`,
which `lego-renew.py` turns into `--dns.resolvers 127.0.0.1:5300`.

### 4. lego "hangs" after writing the TXT record

**When:** after the `PATCH .../zones/lab.local.` succeeds (record written),
lego goes quiet for up to 2 minutes.
**Cause:** lego's propagation pre-check queries the zone's **authoritative
nameservers** directly on `:53`. The zone declares `ns1.lab.local`
(→ `10.11.0.1`) as NS, but nothing serves DNS there (PowerDNS is on
`127.0.0.1:5300`). lego waits for the record to appear on a server that does
not exist.
**Fix:** `challenge.propagation.disable_ans: true` →
`--dns.propagation-disable-ans`. The recursive check via `--dns.resolvers`
(the real authoritative server) still confirms the record.

> It *looks* hung because `lego-renew.py` captures lego's output and logs it
> only after the run. It is actually polling; it would eventually time out.

### 5. The challenge fails even though lego is happy

**When:** lego's pre-check passes, but the order never validates.
**Cause:** **step-ca** validates the TXT record using the **system
resolver** (`127.0.0.11`, Docker embedded DNS), which knows nothing about
`lab.local`. `--dns.resolvers` only affects lego, not step-ca.
**Fix:** make the system resolver able to answer `lab.local`. This scenario
adds a **dnsmasq split forwarder** (`bodsch.dns.dnsmasq`) and points the
container's resolver at it via `dns_servers` in `molecule.yml`.

---

## Docker-specific traps

### You cannot set the container's resolver from inside the container

`/etc/resolv.conf` is a **bind mount** managed by Docker. On a **user-defined
network** it is additionally locked to `nameserver 127.0.0.11` (the embedded
DNS) regardless of what you write into it — and Ansible's `lineinfile`/`copy`
fail with *device busy* anyway (atomic rename over a mountpoint).

**Set it at container-create time** via `dns_servers:` on the platform in
`molecule.yml`. Those become the **upstream** of the embedded resolver, not
the contents of `resolv.conf`.

### The dnsmasq upstream must not point back at `127.0.0.11`

The embedded resolver forwards to dnsmasq; if dnsmasq forwards "everything
else" back to `127.0.0.11`, the embedded resolver forwards it to dnsmasq
again → **infinite loop**. dnsmasq's non-`lab.local` upstream must be a real
external resolver (here `1.1.1.1`).

### dnsmasq must not bind `0.0.0.0:53`

That collides with the embedded resolver on `127.0.0.11:53` and breaks
container-name resolution. Bind a specific address (`10.31.0.1`) with
`bind_only: true`.

### Bootstrap ordering

dnsmasq is *installed* during `prepare`, so it is not listening when the
first packages are installed. The second `dns_servers` entry (`1.1.1.1`) is
the fallback the embedded resolver uses (after a fast "connection refused"
from `10.31.0.1`) until dnsmasq comes up.

---

## Verifying the chain

```bash
# inside the container (molecule login -s full-configured)

cat /etc/resolv.conf                       # -> nameserver 127.0.0.11 (expected!)
systemctl is-active dnsmasq                 # -> active
ss -lnup | grep ':53'                       # dnsmasq on 10.31.0.1:53

dig ns1.lab.local +short                    # -> 10.11.0.1   (chain: embedded→dnsmasq→PowerDNS)
dig @127.0.0.1 -p 5300 lab.local SOA +short # PowerDNS directly

lego-renew.py --preflight                   # trust anchor + ACME reachability
lego-renew.py --log-level INFO --domain lab.local
lego-renew.py --list                        # cert status
```

A successful run shows, per domain:

```
acme: Checking DNS record propagation. [nameservers=127.0.0.1:5300]
The server validated our request          <- step-ca resolved the TXT
Server responded with a certificate.
```

---

## Applying this outside the lab

The `lego-renew.py` knobs that solve the painpoints above are part of the
issuer config and work anywhere, not just here:

| Knob (issuer YAML) | lego flag / env | Use when |
|--------------------|-----------------|----------|
| `ca_certificate` | `LEGO_CA_CERTIFICATES` | the ACME server uses a private/internal CA |
| `challenge.resolvers` | `--dns.resolvers` | the authoritative DNS is not on the system resolver's path (internal / non-standard port) |
| `challenge.propagation.disable_ans` | `--dns.propagation-disable-ans` | the zone's NS records point at hosts that don't actually serve the queried view (split-horizon, single-host labs) |
| `challenge.propagation.rns` | `--dns.propagation-rns` | check propagation via the recursive resolvers instead of the authoritative NS |
| `challenge.propagation.wait` | `--dns.propagation-wait` | skip the check entirely and just wait a fixed duration |

The most important takeaway is structural, not lego-specific: **whatever
resolves DNS for your ACME server must be able to see the challenge record.**
In production that usually means the record lives in real public/internal DNS;
in a lab it means wiring a forwarder so the server's system resolver can reach
the authoritative zone.
