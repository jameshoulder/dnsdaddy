# ADR 0001 — Local DNSSEC validation

**Status:** superseded for the validation engine; retained for its measured
findings. See the note below.
**Date:** 2026-09-03
**Supersedes:** the "Local DNSSEC validation" entry in `docs/roadmap.md`
**Superseded by:** [docs/daddybound/](../daddybound/README.md) — Daddybound v0.1

---

> ## Note added after this ADR was written
>
> This ADR proposes that DNS Daddy establish DNSSEC status by embedding
> **libunbound** as the validator. That is no longer the direction.
>
> Daddybound implements the DNSSEC trust logic itself, from the standards, in
> pure Go. libunbound's role has changed from *the validator* to *a
> differential test oracle*: it is compiled only behind a build tag that no
> shipped build sets, it never produces a Daddybound verdict, and its job is
> to disagree with one so the disagreement can be investigated. See
> [docs/daddybound/validation-lab.md](../daddybound/validation-lab.md).
>
> Two consequences for reading what follows.
>
> **§7's open question is moot.** It asked the maintainer to sign off on
> DNSSEC validation being available only in the Docker image, because cgo
> would have broken the static cross-compiled binaries. Daddybound is pure
> Go, so `CGO_ENABLED=0` holds across all five release platforms and there is
> nothing to trade away.
>
> **The measured sections are still accurate and still used.** The verified
> libunbound API surface, the absence of DoH forwarding, the 16.3 MB RSS
> figure, and the two harness findings — that RFC 6761 special-use names are
> answered NXDOMAIN without a query, and that 0x20 case randomisation breaks
> an exact-match test server — were all measured, and the differential oracle
> and the laboratory server were built from them. That is why this document
> is kept rather than deleted.

---

## 1. What this decides

DNS Daddy currently records the **AD bit an upstream returned**. That is
telemetry about somebody else's conclusion, and `docs/dns-security/dnssec.md`
says so in those words. This ADR decides how DNS Daddy establishes DNSSEC
validation status **locally**, so that an upstream asserting "this is
authentic" is no longer evidence of anything.

Everything below marked **measured** was run in this repository's development
environment on 2026-09-03 against libunbound 1.19.2. Nothing here is recalled
from documentation.

---

## 2. The constraint that drives the decision

**DNS Daddy is a pure-Go, statically linked, cross-compiled project today, and
that is not incidental.**

| Where | Setting |
|---|---|
| `Makefile:14` build | `CGO_ENABLED=0` |
| `Makefile:80` release | `CGO_ENABLED=0` across `linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64` |
| `Dockerfile:17,24` | `CGO_ENABLED=0`, with a comment saying the SQLite driver is pure Go *so that* this works |
| `.github/workflows/ci.yml:123` | `CGO_ENABLED: 0` |

The SQLite driver is `modernc.org/sqlite` — a pure-Go transliteration —
specifically to keep this property. Introducing cgo unconditionally would:

* break cross-compilation of all five release targets from one CI runner
  (each needs a target cross-toolchain **and** a target build of libunbound;
  the two `darwin/*` targets need osxcross);
* end the static binary, so the runtime image needs shared libraries;
* require libunbound on any developer machine, including macOS.

**Any design that makes the default build depend on cgo is unacceptable.** The
decision below is shaped around that.

---

## 3. Is libunbound suitable? Verified, not assumed

The brief requires confirming the current libunbound API provides specific
capabilities. Checked against `/usr/include/unbound.h` from
`libunbound-dev 1.19.2-1ubuntu3`:

| Requirement | Verdict | Evidence |
|---|---|---|
| DNSSEC validation | Yes | `ub_resolve`, `ub_resolve_async` |
| secure / bogus / insecure results | Yes | `ub_result.secure`, `.bogus`; insecure is `secure==0 && bogus==0` |
| Full DNS answer packets | Yes | `.answer_packet`, `.answer_len` — **measured**: 183-byte wire response unpacked cleanly with `miekg/dns` |
| Reason for bogus | Yes | `.why_bogus` — **measured**: `validation failure <www.example.dnsdaddylab. A IN>: signature crypto failed from 127.0.0.1` |
| RFC 5011 trust-anchor maintenance | Yes | `ub_ctx_add_ta_autr`, plus `auto-trust-anchor-file`. **Measured**: an `_ta-8100.<zone> NULL` query was observed on the wire — that is RFC 8145 key-tag signalling, which is the RFC 5011 machinery running |
| Cancellation / time bounds | Yes | `ub_resolve_async` + `ub_cancel`, `ub_fd`, `ub_process`, `ub_wait` |
| Forwarding through configured upstreams | Yes | `ub_ctx_set_fwd`, accepts `IP@port` |
| DNS-over-TLS | Yes | `ub_ctx_set_tls`, `tls-upstream`, `tls-cert-bundle` |
| Explicit memory/cache controls | Yes | `msg-cache-size`, `rrset-cache-size`, `key-cache-size`, `neg-cache-size` via `ub_ctx_set_option` |

Also present: `ub_ctx_add_ta`, `ub_ctx_add_ta_file`, `ub_ctx_config`,
`ub_ctx_zone_add`, `ub_ctx_data_add`, `ub_strerror`, `ub_ctx_async`.

**Conclusion: libunbound is suitable and no Go wrapper is needed.** A small
auditable cgo adapter over ~10 functions is sufficient. No third-party wrapper
is adopted.

### 3.1 What libunbound cannot do: DoH forwarding

DNS Daddy supports four upstream schemes (`internal/resolver/upstream.go:47`):
`udp://`, `tcp://`, `tls://`, `https://`.

Unbound's compiled-in option table was inspected directly
(`strings /usr/sbin/unbound`). It contains `tls-upstream` and `http-endpoint`
— but **`http-endpoint` is the DoH *server* side**. There is no option for
forwarding *to* a DoH resolver, and no `forward-*http*` option of any kind.

**`https://` upstreams cannot be preserved through libunbound.** Per the brief,
this must not be silently downgraded to cleartext. See §6.

---

## 4. Options considered

### Option A — embedded libunbound, behind a build tag *(recommended)*

`internal/dnssec` holds a pure-Go interface and a no-op default.
`internal/dnssec/unbound` holds the cgo adapter behind
`//go:build cgo && dnssec_unbound`.

**Measured:** with `CGO_ENABLED=0`, a package containing only cgo files fails
with `build constraints exclude all Go files` — the exclusion is total and
compile-time. The default build cannot accidentally acquire a libunbound
dependency.

* Default build, all five release targets, the static binary and CI: **entirely
  unchanged**. Zero impact when validation is off, as the brief requires.
* The Docker image — the documented primary deployment — is built with
  `CGO_ENABLED=1` and `apk add unbound-libs`, so validation is available there.
* **Measured:** links `libunbound.so.8`, `libssl.so.3`, `libcrypto.so.3`.
* **Measured:** 16.3 MB RSS for a Go process with a libunbound context holding
  15 MB of configured caches. Comfortable against the 1 GB reference target.

**Cost, stated plainly:** validation is available in the container image and in
binaries a user builds with the tag. It is **not** available in the
cross-compiled release tarballs. The feature's availability depends on how DNS
Daddy was installed, and that has to be documented prominently rather than
buried.

### Option B — supervised local `unbound` process

DNS Daddy stays 100% pure Go and supervises a bundled `unbound` on loopback.

* Release engineering completely untouched, including the tarballs.
* But the validator's verdict arrives as a **DNS message**, so DNS Daddy is
  back to reading an AD bit — from a local, controlled validator, which is a
  real improvement, but it collapses the result space: `secure` is AD=1,
  `bogus` is indistinguishable from any other SERVFAIL, and `why_bogus` is not
  available without the control socket.
* The brief requires distinguishing secure / insecure / bogus / indeterminate
  and capturing a reason. Option B cannot do that cleanly.
* Adds process supervision, a second config file, a second failure domain, and
  a second thing to restart on upgrade.

### Option C — write a validator with `miekg/dns`

**Explicitly forbidden by the brief, and correctly.** Chain building,
authenticated denial (NSEC/NSEC3, including opt-out), wildcard proofs, and
algorithm-rollover policy are where DNSSEC implementations get subtly wrong,
and a subtly wrong validator that reports "secure" is worse than no validator.

## 5. Decision

**Option A.** Embedded libunbound through a small first-party cgo adapter,
excluded from the default build by a build tag, enabled in the Docker image.

Option B remains the documented fallback if the container-only limitation
proves unacceptable in review.

---

## 6. Consequences

### Unsupported combinations — rejected at startup, never downgraded

| Combination | Behaviour |
|---|---|
| `dnssec_validation: observe\|enforce` + any `https://` upstream | **Startup error.** libunbound cannot forward over DoH (§3.1). Downgrading to cleartext would silently remove the encryption the operator configured. |
| `dnssec_validation: observe\|enforce` + `upstream_mode: race` | **Startup error.** Race mode returns the first upstream to answer; libunbound performs its own upstream selection, so DNS Daddy would be asserting race semantics it no longer controls. |
| `dnssec_validation: observe\|enforce` on a binary built without the tag | **Startup error** naming the build, not a silent fall back to `off`. |
| `dnssec_validation: off` | Everything above is permitted, exactly as today. |

`dnssec_telemetry` is kept, unchanged, and is not repurposed.

### Build and release

* `Makefile`: default target unchanged; new `build-validating` target.
* `make release`: unchanged, still `CGO_ENABLED=0`, still five targets.
* `Dockerfile`: runtime image gains `unbound-libs`; build stage gains
  `CGO_ENABLED=1` and `unbound-dev`. The image stops being fully static.
* CI: existing pure-Go job unchanged; a second job builds and tests with the
  tag on `linux/amd64` only.

### Memory

Explicit budgets, set through `ub_ctx_set_option` and documented:
`msg-cache-size: 4m`, `rrset-cache-size: 8m`, `key-cache-size: 2m`,
`neg-cache-size: 1m`, `num-threads: 1`. libunbound's caches are **not**
disabled — doing so would repeat DNSKEY/DS validation for every client query.

---

## 7. The decision that needs sign-off

Option A means **local DNSSEC validation ships in the Docker image but not in
the release tarballs.**

That is a real product limitation, and the alternative (Option B) trades result
quality for uniform availability. I recommend A and can implement B instead.
This is the only open question in this ADR.

---

## 8. Test architecture — proven, not proposed

The brief requires deterministic offline tests. The approach was built and run
before this ADR was written:

1. Generate an ECDSA P-256 KSK with `miekg/dns` in-process.
2. Sign a small zone (`A`, `DNSKEY`, `SOA`, `NS`) with `dns.RRSIG.Sign`.
3. Serve it from a Go authoritative stub on `127.0.0.1:0`.
4. Point libunbound at it with `ub_ctx_set_fwd`, anchored with `ub_ctx_add_ta`
   on our own generated key, `do-not-query-localhost: no`.

**Measured results:**

```
valid    -> SECURE (secure=1 bogus=0 rcode=0)  answer: 192.0.2.1  AD=true
tampered -> BOGUS  (secure=0 bogus=1)          answer withheld    AD=false
            why_bogus: validation failure <www.example.dnsdaddylab. A IN>:
                       signature crypto failed from 127.0.0.1
```

The tampered case **is** the milestone's primary threat case: an upstream
supplied DNS data that cannot validate, and the local validator did not accept
it. No public DNS was involved.

### Two findings that will otherwise cost hours

* **Do not use `.test`, `.invalid`, `.localhost` or `home.arpa` for test
  zones.** Unbound blocks RFC 6761 special-use names by default and answers
  NXDOMAIN without querying, which looks exactly like a broken forwarder. The
  first version of this experiment failed for that reason. Test zones use
  `example.dnsdaddylab.`
* **The authoritative stub must match query names case-insensitively.**
  Unbound randomises query-name case (0x20 anti-spoofing), so an exact string
  comparison answers NXDOMAIN to the validator's own queries.

---

## 9. What this does not claim

DNSSEC does not encrypt DNS, does not prove a domain is safe, does not protect
against a malicious domain owner who signs their own zone correctly, and does
not provide end-to-end validation at the stub client — the client is trusting
DNS Daddy's AD bit over the local network. `docs/dns-security/dnssec.md` will
say all of this.

`Insecure` is a **successful** outcome meaning "provably outside the DNSSEC
chain of trust", not a failure and not a synonym for `indeterminate`.
