# DNS Daddy Security Testing — PR #36

**Project:** DNS Daddy  
**Repository:** `jameshoulder/dnsdaddy`  
**Tested commit:** `4c260b0b1d0e450e34289916cdbacc6fc88cde27`  
**Commit:** Merge pull request #36 — *P0: dashboard-managed resolver access, and an installer that finishes the job*  
**Test date:** 28 August 2026  
**Environment:** Ubuntu 24.04 LTS on an authorised Azure Cyber Range VM  
**Scanner:** Tenable Vulnerability Management / Nessus 10.12.4

> This document records one controlled dynamic-security assessment of a specific DNS Daddy build. It is not a claim that DNS Daddy is vulnerability-free, and results should not be generalised beyond the tested build, configuration, scanner coverage, and environment.

## Objective

The objective was to measure whether deploying DNS Daddy introduced identifiable vulnerabilities or unexpected network exposure, using a before/after baseline and a separate web-application assessment.

The assessment was deliberately scoped to a single authorised lab VM. Safe checks were enabled and disruptive, thorough, experimental, malware, OT and brute-force style testing were not used.

## Test configuration

DNS Daddy was deployed using the PR #36 Docker installer in VPS-safe mode.

Observed runtime exposure after deployment:

- DNS service: TCP/UDP 53 on the VM network interface.
- Dashboard/API: `127.0.0.1:8080` only.
- Docker/containerd present as expected.
- Dashboard was not deliberately exposed through the Azure network interface for testing.

## Method

Four Tenable scans were used:

1. **Baseline Basic Network Scan** — before Docker/DNS Daddy deployment.
2. **Post-deployment Basic Network Scan** — after Docker and DNS Daddy were installed.
3. **Legacy Web App Scan** — against the local dashboard on `127.0.0.1:8080`.
4. **Advanced Network Scan** — deeper post-deployment host/network assessment using safe, non-disruptive settings.

The baseline and post-deployment network scans used the same target and comparable settings so changes in findings could be attributed more reliably to the deployment.

## Results

| Scan | Critical | High | Medium | Low | Info | Total |
|---|---:|---:|---:|---:|---:|---:|
| Baseline Basic Network Scan | 0 | 0 | 1 | 0 | 71 | 72 |
| Post-deployment Basic Network Scan | 0 | 0 | 1 | 0 | 78 | 79 |
| Legacy Web App Scan | 0 | 0 | 0 | 2 | 9 | 11 |
| Advanced Network Scan | 0 | 0 | 1 | 0 | 78 | 79 |

### Network-scan interpretation

The single Medium finding in the baseline, post-deployment Basic scan and Advanced scan was **Tenable plugin 51192 — SSL Certificate Cannot Be Trusted** on TCP/8834. This was associated with the Nessus scanner's own certificate and was present before DNS Daddy was installed.

Accordingly, the before/after network assessment identified:

- **0 new Critical findings attributable to DNS Daddy**
- **0 new High findings attributable to DNS Daddy**
- **0 new Medium findings attributable to DNS Daddy**
- **0 new Low findings attributable to DNS Daddy**

The increase in informational findings after deployment was consistent with the expected additional attack-surface inventory. Tenable detected DNS, Docker/containerd and the running DNS Daddy container.

Tenable enumerated TCP/UDP 53 as listening after deployment and identified the DNS Daddy container. It also observed that the container's dashboard mapping remained bound to `127.0.0.1:8080`, while DNS was published to port 53.

### Web-application findings

The Legacy Web App Scan returned two Low findings:

1. **26194 — Web Server Transmits Cleartext Credentials**  
   The dashboard was tested over local HTTP. In the tested VPS-safe deployment, the dashboard was bound to loopback, which substantially limits network exposure; however, the finding is relevant to any deployment that makes the dashboard reachable beyond the local host without TLS.

2. **42057 — Web Server Allows Password Auto-Completion**  
   DNS Daddy uses `autocomplete="current-password"` for the admin password field. This is intentional and supports modern password managers. The scanner finding should therefore be reviewed contextually rather than automatically treated as a defect.

The web scan also generated informational observations including SPA-style non-404 behaviour and permissive HTTP-method responses on `/`. These are useful hardening leads but were not reported by Tenable as confirmed vulnerabilities.

## Positive security observations

The assessment provided evidence that:

- the expected DNS service was exposed on TCP/UDP 53;
- the management dashboard remained restricted to loopback in VPS-safe mode;
- Tenable did not identify unexpected remotely exposed dashboard port 8080 in the network scans;
- the web application returned security headers including a restrictive Content Security Policy, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `X-Frame-Options: DENY`;
- the Advanced Network Scan completed with **Safe Checks enabled**, while thorough and experimental tests remained disabled.

## Hardening actions raised by the assessment

The following should be tracked as engineering/security work rather than treated as proof of exploitable vulnerabilities:

- **Dashboard transport:** make the requirement for TLS explicit when the dashboard is made reachable beyond loopback; consider stronger warnings or deployment guardrails.
- **HTTP methods:** review the static-dashboard handler and consider returning `405 Method Not Allowed` for methods other than those intentionally supported (for example GET/HEAD for static content).
- **SPA fallback:** review whether unknown non-asset paths should always return the SPA document or whether some paths should return a true `404 Not Found`.
- **Autocomplete finding:** document the intentional use of `autocomplete="current-password"` and retain it unless a concrete threat model justifies disabling it.

## Limitations

This assessment does **not** prove the absence of vulnerabilities. In particular:

- the network scans used safe checks and did not enable disruptive/thorough/experimental testing;
- the web scan was an unauthenticated/limited DAST assessment of the local dashboard;
- the assessment did not attempt exploitation;
- scanner coverage is limited to the plugins and signatures available at test time;
- this document covers dynamic Tenable testing, not a complete source-code review;
- results apply to the tested commit and deployment configuration.

## Recommended next assurance steps

1. Create GitHub issues for the HTTP/TLS and HTTP-method hardening observations.
2. Run and retain results from the repository's static/dependency/container security tooling (for example CodeQL, Semgrep, gosec, govulncheck and Trivy where configured).
3. Add or extend unit/integration tests for any hardening changes.
4. Re-run the web-application scan after remediation and record whether findings change.
5. Repeat dynamic testing periodically for material releases.

## Evidence retained

- `HoulderVM_-_Initial_Vulnerability_Scan_p5r0qq.pdf`
- `HoulderVM_-_DNS_Daddy_PR36_Scan_lrxen2.pdf`
- `HoulderVM_-_DNS_Daddy_PR36_Web_App_Scan_9n07h7.pdf`
- `HoulderVM_-_DNS_Daddy_PR36_Advanced_Scan_q0ubpu.pdf`
- Deployment screenshots and terminal output recording the tested commit and runtime port bindings.

## Summary

In this authorised Azure lab assessment, deploying DNS Daddy PR #36 increased the expected informational attack-surface inventory but did **not** introduce any new Critical, High, Medium or Low findings in either the Basic or Advanced Tenable network scans. A separate Legacy Web App Scan identified two Low-severity observations requiring contextual review and produced additional hardening leads. These results are useful security-assurance evidence for the tested build, while remaining subject to the limitations above.
