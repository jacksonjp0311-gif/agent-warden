# Security policy

agent-warden is a security tool, so bypasses are the bugs we care about most.

## Reporting a vulnerability

Please report privately via **GitHub Security Advisories**: *Security →
Report a vulnerability* on this repository. Don't open a public issue. Include:

* the policy you used (or a minimal one),
* what the agent did (a `rogue-agent`-style reproduction is ideal),
* what you expected warden to do, and the kernel version / whether Landlock
  and seccomp were active (warden prints this at startup).

We aim to acknowledge reports within 7 days and will credit reporters unless
asked not to.

## Scope

In scope:

* Performing a denied action through the gateway or proxy
* Escaping Landlock or seccomp confinement as configured by warden
* Surviving the kill switch, or preventing a halt that should happen
* Undetected modification of a signed audit log
* Secrets leaking into the audit log

Known limitations listed in the README's threat model (TLS opacity, DNS/UDP
when `block_udp` is off, same-UID without kernel sandboxing, and so on) are
not vulnerabilities by themselves. Improvements are still welcome.

## Supported versions

Only the latest release on `main` receives fixes while the project is pre-1.0.
