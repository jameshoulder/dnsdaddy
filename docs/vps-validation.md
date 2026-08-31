# Manual validation on a public VPS

Everything here needs a machine with a public address and inbound 80, 443 and
53 — which is why it is a script for you to run rather than a test in CI. The
target it was written for is Ubuntu 24.04.4 at `172.236.31.102`.

**Nothing in this file has been run by the project.** Rows in
[deployment-matrix.md](deployment-matrix.md) stay unticked until a real run
produces real output. Please paste failures back rather than working around
them.

## Before you start

Let's Encrypt validates by connecting **to this machine, from the internet**.
The installer cannot see your cloud firewall, so check it first — on the VPS
this was first tested against, a closed firewall was the whole reason
certificate issuance failed.

```bash
# On the VPS. Both must be reachable from OUTSIDE, not just bindable here.
sudo ss -lntp | grep -E ':(80|443)\b' || echo "nothing listening yet (expected before install)"
```

From **your laptop**, not the VPS:

```bash
# Anything other than a refused/timed-out connection means something answers.
nc -zv 172.236.31.102 80
nc -zv 172.236.31.102 443
```

If those hang or refuse before Caddy is installed, that is expected. Re-run
them after step B or C: if they still hang **after** Caddy is running, the
packets are being dropped upstream and no amount of retrying will issue a
certificate. In Linode that is **Cloud Firewall**; open inbound TCP 80 and 443.

DNS needs UDP 53 and TCP 53 as well. Opening them does **not** make this an
open resolver — which clients may query is decided by the client ACL under
Networks, not by the firewall.

---

## A. SSH tunnel mode (the default)

```bash
sudo ./deploy/install-docker.sh --vps --yes
```

Expect: dashboard on `127.0.0.1:8080`, nothing published.

```bash
# On the VPS: loopback answers, the public address does not.
curl -sS http://127.0.0.1:8080/api/v1/health; echo
curl -sS --max-time 5 http://172.236.31.102:8080/api/v1/health && echo "FAIL: 8080 is public" || echo "PASS: 8080 is not public"
```

From your laptop:

```bash
ssh -L 8080:127.0.0.1:8080 root@172.236.31.102
# then open http://127.0.0.1:8080 and log in
```

**Record:** does login succeed through the tunnel?

---

## B. Hostname HTTPS

Point an A record at the VPS first, and let it propagate:

```bash
dig +short admin.example.com     # must print 172.236.31.102
```

```bash
sudo DNSDADDY_HTTPS_HOSTNAME=admin.example.com ./deploy/install-docker.sh --https --yes
```

Expect the installer to print `admin.example.com resolves to 172.236.31.102,
which is an address on this machine`, then the reachability section, then what
it is about to do, then issuance.

---

## C. Raw-IP HTTPS

```bash
sudo DNSDADDY_HTTPS_HOSTNAME=172.236.31.102 ./deploy/install-docker.sh --https --yes
```

This uses Let's Encrypt's `shortlived` profile — the only one under which it
issues IP certificates. The certificate is valid for about six days and Caddy
renews it automatically.

---

## D. Certificate verification

The point of this step is that **verification is not disabled**. `curl -k` does
not count and must not be used to declare success.

```bash
# From your laptop. No -k anywhere.
curl -sS https://admin.example.com/api/v1/health; echo      # hostname
curl -sS https://172.236.31.102/api/v1/health; echo         # raw IP

# Who issued it, and how long is it good for?
echo | openssl s_client -connect 172.236.31.102:443 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

**Record:** issuer should be Let's Encrypt. For the IP certificate, `notAfter`
minus `notBefore` should be about 160 hours.

---

## E. HTTP to HTTPS

```bash
curl -sS -o /dev/null -w '%{http_code} -> %{redirect_url}\n' http://172.236.31.102/
```

**Record:** a 30x to the `https://` URL. A `200` here means something is
serving the dashboard in plaintext — stop and report it.

---

## F. The backend must stay private

The single most important check in this file.

```bash
# From your laptop.
curl -sS --max-time 5 http://172.236.31.102:8080/api/v1/health \
  && echo "FAIL: backend is published" || echo "PASS: backend is not reachable"

# On the VPS: the published port must be bound to loopback, not 0.0.0.0.
sudo ss -lntp | grep ':8080'
docker compose ps --format '{{.Service}} {{.Ports}}'
```

**Record:** `ss` should show `127.0.0.1:8080`. Anything bound to `0.0.0.0:8080`
is a failure regardless of what the firewall does.

---

## G. An unapproved client is refused

From a machine **not** in any permitted range:

```bash
dig @172.236.31.102 example.com
```

**Record:** `status: REFUSED`. Note that `SERVFAIL` is a different answer — it
means the ACL let the query through and resolution failed, which is not what
this step is testing.

---

## H. Granting a client works

In the dashboard: **Networks → add** your client's public IP as a `/32`, tick
**Allow this network to use DNS Daddy**, save. A publicly routable range will
ask you to confirm; that prompt is the open-resolver guard and is expected.

```bash
dig @172.236.31.102 example.com     # now NOERROR
```

**Record:** did it work **without restarting anything**?

---

## I. Revocation works without a restart

Untick the box, save, and immediately:

```bash
dig @172.236.31.102 example.com     # REFUSED again
```

**Record:** how long it took to take effect.

---

## J. Re-running the installer

```bash
sudo ./deploy/install-docker.sh --https --yes    # same arguments as before
```

**Record:** no duplicate site block in `/etc/caddy/Caddyfile`, a timestamped
backup beside it, and the deployment still working afterwards.

```bash
grep -c 'reverse_proxy 127.0.0.1:8080' /etc/caddy/Caddyfile   # must be 1
ls -la /etc/caddy/Caddyfile*
```

---

## K. A failed TLS setup returns to tunnel mode safely

Force a failure, deliberately — a name that cannot possibly validate:

```bash
sudo DNSDADDY_HTTPS_HOSTNAME=not-a-real-host.invalid ./deploy/install-docker.sh --https --yes
```

**Record all of:**

```bash
# 1. The dashboard is back on loopback and nothing is published.
curl -sS --max-time 5 http://172.236.31.102:8080/ && echo "FAIL" || echo "PASS"

# 2. Secure cookies were NOT left on — this is what makes the tunnel usable
#    rather than merely safe. With it set, the browser will not send the
#    session cookie over http://127.0.0.1:8080 and login fails silently.
grep -E '^DNSDADDY_(SECURE_COOKIES|BASE_URL|TRUSTED_PROXY_CIDRS)' .env || echo "PASS: all three reverted"

# 3. The previous Caddyfile is back, byte for byte.
ls -la /etc/caddy/Caddyfile*

# 4. Login still works through the tunnel.
ssh -L 8080:127.0.0.1:8080 root@172.236.31.102
```

**Record:** the installer should name the actual cause rather than guessing.
For an unresolvable name expect wording about DNS, not about firewalls.

---

## Then

```bash
docker compose exec dnsdaddy dnsdaddy doctor
```

**Record:** the `Dashboard backend` line. In HTTPS mode it should PASS and name
the public URL; in tunnel mode it should PASS and say the dashboard is private.
A loopback dashboard reported as a failure is itself a bug — please report it.

Paste the output of each **Record** step into the PR, and update the matching
row in [deployment-matrix.md](deployment-matrix.md) only for steps that were
actually run.
