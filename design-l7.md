<!--
The L7 rationale lives here rather than in design.md: design.md keeps a
one-paragraph summary and links here. Cross-references to "design.md" below
mean that file, not this one.
-->

# L7 destination-identity enforcement (TLS SNI / HTTP Host / QUIC)

The L3/L4 verdict allows a destination IP. A hostname rule resolving to a
shared CDN/edge IP (Cloudflare, Akamai, Fastly) therefore opens that `/32` for
**every** tenant behind it: an attacker who registers their own domain on the
same CDN reaches the already-allowed edge IP, and the L4 verdict cannot tell
the two apart. This layer pins *which* hostname a flow to a DNS-derived IP may
reach. It never widens an L4 verdict — only narrows one.

## Where it runs

At `cgroup_skb/egress` only (`bpf/sni.h`, `#included` by `originbpf.c`), as a
narrowing filter after the L4 allow. TC is post-NAT with no socket and no
reassembly path, so it cannot compute an L7 verdict; it stays the run-wide L4
backstop. If the cgroup hook detaches or fails to load, enforcement degrades to
TC's L4-only verdict and the shared-edge hole reopens for the run — the same
degradation posture design.md records for container attribution, which rides
the same hook.

## Kernel and oracle

The kernel decides WHETHER a segment needs adjudication — scope check, identity
gate, per-flow state — never WHO is allowed. Anything that opens an identity (a
ClientHello, an HTTP request line, a QUIC Initial, whose AES-GCM the verifier
will never accept) it copies to a ringbuf and, under enforce, drops. The oracle
(`pkg/origin/l7.go`, parsing via `pkg/sni`) reassembles the handshake, matches
the recovered name against policy, and writes the verdict into `map_l7_flow`;
the client's retransmit is then admitted or dropped by the kernel.

**There is deliberately no in-kernel name match.** An earlier inline TLS fast
path over a name-keyed allow map was removed: a no-expiry kernel name cache is
a weaker second copy of the matcher, and every lifecycle it lacked — derived
TTLs, policy reload, mixed allow/deny ports, per-IP pinning — had to be
re-imposed on it, several times wrongly. One policy plane means the matcher's
answer under the live rules is the only answer. The cost is one retransmit RTO
per new TLS flow, which HTTP, QUIC, split hellos and derived targets paid
anyway. It also means no path bypasses the matcher, which is what makes the
pinning measurement below complete by construction.

## What counts as policy

The same two tiers the DNS query gate applies: hostname rules first, then CNAME
targets derived from allowed responses (`Server.DerivedAllowPorts`), with an
explicit deny beating both. The second tier is not optional — a client that
legitimately dialed a CNAME target directly presents that *target* as its
SNI/Host, which matches no rule, and a rules-only matcher would deny every such
flow. Derived names are port-scoped by the ports they inherited from their
origin, and expire exactly when the derived TTL does.

A duplicate-SNI hello (two `server_name` extensions, or two `host_name` list
entries) is rejected as malformed rather than resolved first- or last-wins:
with two names in flight, the enforcer and the server could pick different
ones, which is the shared-edge swap this layer exists to close.

## Identity is per connection — and for QUIC, per attempt

**TLS.** The SNI is fixed at the handshake, so the connection's first
adjudicated identity governs it.

**HTTP** gets the same contract deliberately: the first request's `Host` pins
the connection. Re-adjudicating every request line was tried and removed — the
kernel can only classify one segment's leading bytes, so a pipelined request
mid-segment always evaded it while honest clients paid the false positives. The
**keep-alive Host change is therefore a documented residual**, subsuming the
mid-segment one: it covers accidental cross-tenant reuse only as far as real
clients do it (connection pools key by host), and the strong guarantee remains
TLS SNI. The parser still rejects smuggling shapes (duplicate `Host`, obs-fold,
Host/target mismatch) on the adjudicated request.

**QUIC** cannot use per-connection state alone: one UDP socket can carry a
second QUIC connection whose Initial names a different tenant, and the flow key
cannot tell them apart. The Initial's Destination Connection ID is therefore
the connection-attempt identity in EVERY flow state, for every version the
decryptor supports (v1, v2, draft-29 — pinned kernel↔userspace by test). The
kernel stamps it when a punt opens a cycle; the oracle writes it back with BOTH
terminal verdicts; an Initial whose DCID disagrees re-enters adjudication with
a fresh budget whatever the prior verdict was. ALLOWED must not admit an
unadjudicated SNI, and DENIED — a map entry with no TTL — must sentence one
attempt, not every later connection on the socket. A matching DCID rides its
verdict, because re-pinning would drop the connection's only copies forever.

The identity is the exact DCID, **not a hash**: the client picks it, so a
folded identity is forgeable — a second connection could search for a colliding
value (a 32-bit fold is seconds of local compute) and ride the verdict with its
SNI never parsed.

## The coalesced walk

The Initial need not be the first packet of the datagram. A UDP datagram may
coalesce several QUIC packets (RFC 9000 §12.2) and a receiver processes each
one it can, so a naive first-packet check is evaded by prepending a
0-RTT/Handshake header. Both the kernel gate and the userspace decryptor
therefore walk the coalesced packets, skipping decodable non-Initial long
headers by their Length, and do **not** stop at the first Initial — anything
coalesced behind an adjudicated one would otherwise ride its verdict.

**One datagram, one connection.** Every long-header packet must carry the same
DCID, which RFC 9000 §12.2 already requires of senders, so no conformant client
is refused. That one rule covers both a second Initial under a different DCID
and a 0-RTT/Handshake belonging to some other connection. Packets with the
*same* DCID are one attempt — a ClientHello spanning several Initials rides
together.

**The cap is verifier budget, not protocol shape.** `L7_QUIC_MAX_COALESCED`
(pinned equal to `sni.MaxCoalescedPackets`) costs ~20k of `cg_origin_egress`'s
1M instruction limit per rung. Raising it to 12 took the program from 236k to
450k on a 6.8 kernel and past 1,000,001 on the newer kernel CI runs — where it
fails to load and the whole cgroup hook, L4 enforcement included, silently does
not attach. Measure on CI's kernel before changing it.

**Uncertainty.** A datagram the walk cannot resolve — an unskippable header
(unknown version, Retry) *before* any Initial, still-skippable packets past the
cap, or mixed connection IDs — is dropped with **no flow state**, and that check
runs *before* the per-flow terminal ladder so an already-ALLOWED flow cannot
short-circuit past it. One shape is deliberately tolerated: an unskippable
packet *behind* a found Initial ends the walk cleanly, because a receiver that
cannot parse a coalesced packet cannot reach anything after it either — this is
the greased reserved-version trailer real clients append. The uncertain drop is
not an adjudication punt (which would park the flow PENDING on a sample the
oracle may resolve to "no Initial", stranding the socket) but it does emit a
report-only refusal record.

Consequently **every QUIC sample the oracle receives carries an Initial the
kernel recognized**, so a datagram the decryptor then finds no Initial in is
kernel/parser drift and fails closed with a record. A datagram the walk clears
of any Initial — short headers, a lone Handshake/0-RTT — carries no
first-flight identity and is never punted or budgeted: on a PENDING flow it
fails closed, and with no flow state it rides as established traffic, exactly
as TLS post-handshake records do.

## GSO batches

At `cgroup_skb/egress` a UDP GSO batch (`UDP_SEGMENT`, which quic-go and
Chromium both use) arrives as ONE skb spanning every datagram of the send: this
hook runs in `ip_finish_output`, before `ip_finish_output_gso` splits it. The
walk models a single datagram, so two things follow.

A first flight padded across N Initial datagrams walks as N packets rather than
N datagrams, so a ClientHello needing a fifth datagram — reachable with a
post-quantum key share plus ECH — exceeds the cap and is refused. That fails
closed, and fixing it means a cheaper walk, not more rungs.

The second is why `l7_quic_gso_tail` exists. The walk's answer describes only
the bytes it reached, and a short header legitimately ends a datagram (RFC 9000
§17.3: no Length, runs to the end), so the walk can stop well before the end of
a batch while the stack still emits the remaining segments as datagrams of
their own. A "no Initial here" answer covering part of a send is not an answer
about the send. Every segment boundary past the walk must therefore start with
a short header too; a long header there is uncertain and fails closed, since it
means an identity-bearing datagram sits in bytes nothing classified. Bulk 1-RTT
GSO (every segment a short header) is untouched.

## Fail-closed posture

A punted flow is dropped and the decision awaits the oracle (one retransmit RTO
per new flow). The rejected optimistic alternative — pass the first flight,
kill on deny — leaks the whole pre-verdict flight (initcwnd ≈ 14.6 KB, up to a
64 KB GSO super-skb) of attacker-controlled bytes to an arbitrary CDN-fronted
endpoint, which is the exact channel this feature closes. LRU eviction, a full
ringbuf and an exhausted punt budget therefore all deny.

The one deliberate exception is the identity gate's **no-state arm**:
continuation bytes on a flow with no map entry (a pre-existing connection at
attach, an LRU-evicted verdict) pass rather than kill a live allowed session.
For TLS that is post-handshake records; for QUIC, datagrams carrying no Initial
identity. It is a documented residual, identical in class for both protocols: traffic
shaped like a continuation reaches this arm without an adjudicated first
flight. At a real shared edge such packets belong to no connection and die at
the terminator — the identity-bearing first flight is what routes, and that is
always adjudicated.

## Scope maps are rebuilt, not patched

`map_l7_scope`/`_v6` (which destinations are L7-governed at all) have no expiry
and no per-name reverse index, so a policy reload flushes them wholesale and
re-warms both allow tiers from the tracked-hostname replay. A dropped rule's
IPs stop being governed, and dead entries cannot accumulate until the
fixed-size maps fill — which would silently fail OPEN every newly resolved
destination (a full map warns loudly and counts; capacity is 16k per family).
The brief unscoped window between flush and re-warm fails toward the pre-L7
posture, only on reload.

The flush and the re-warm are **one indivisible step**. The replay re-scopes
only from the firewall-installed allow tiers, so `ApplyRulesToTrackedHostnames`
refuses to run — flushing nothing — if called before `SetFirewall`. Otherwise
the flush would wipe every scoped destination with nothing to restore it,
turning SNI enforcement off for the rest of the run while the daemon still
reported L7 active. The flush drains via batch map operations (a handful of
syscalls for a full 16k map, versus two per entry) so it does not stall the
DNS-resolution scope writes it briefly locks out.

## Mode ladder and rollout

An independent `L7_MODE` gate (OFF/OBSERVE/ENFORCE) lets L7 be dark-launched
while origin enforcement is already on. The ENFORCE drop still defers to
`audit_mode_active()` exactly as `verdict_action` does, so audit mode remains
the run's single source of truth for "log, never block".

Rollout is observe-first (`--tls-sni=observe`): parse, punt and emit
`l7_would_block` telemetry without dropping, so the would-deny set and the
first-segment parse coverage can be measured on real CI before
`--tls-sni=enforce` turns drops on. QUIC is **parsed, not blocked** — Initial
keys derive deterministically from the client's Connection ID plus a public
per-version salt (RFC 9001), so HTTP/3 keeps working; an unknown QUIC version
fails closed.

## Observability

Identity-gate refusals open no adjudication cycle, so their incidence is
measured by counters logged at teardown, split so the observe-first rollout
stays legible:

- A **fresh** refusal (the flow's SYN was seen, so this is a genuine first
  flight) counts `L7_STAT_GATE_REFUSED` **and** emits a report-only audit
  record — `l7_blocked` under enforce, `l7_would_block` under observe —
  carrying a snippet of the refused bytes and the cookie→pid/step attribution,
  so an operator debugging a hung `ssh.github.com:443` or a QUIC-version drop
  sees more than an L4 ALLOW.
- A **no-state** refusal (no SYN: a segment starting mid-record after LRU
  eviction, or a pre-existing connection at attach) is overwhelmingly
  evicted-flow ciphertext whose arbitrary first byte misses the four TLS record
  types. It counts a separate `L7_STAT_GATE_NO_STATE` and is deliberately not
  recorded — high-volume noise that would make `GATE_REFUSED` unreadable as the
  number the enforce decision rests on.

A per-rule `l4-only` opt-out is future work, to add only if the measured
incidence warrants it. It does not exist yet; do not document it as available.

## Ports

Adjudication is port-scoped by construction: the scope bits mean TCP/443 = TLS,
TCP/80 = Host, UDP/443 = QUIC, and `l7_narrow_scope` narrows on proto+port. So
every other port on a scoped IP — `ssh.github.com:22`, SMTP, DNS — stays
governed by the L4 verdict alone.

The TLS and Host dimensions additionally cover the **CDN alternate ports**
(`l7_alt_https_port` / `l7_alt_http_port` in `bpf/sni.h`, mirrored by
`bpf.AltHTTPSPorts` / `bpf.AltHTTPPorts`): the big CDNs terminate the *same
shared edge* on 2053/2083/2087/2096/8443 and 2052/2082/2086/2095/8080/8880. An
all-ports hostname allow opens the edge `/32` on every port, so scoping only
the canonical pair would govern the identity on 443/80 while leaving the same
edge L4-only everywhere else it terminates TLS.

Those ports are **lenient**, unlike 443/80: a first flight there that is not
TLS/HTTP passes to the L4 verdict (counted as `L7_STAT_ALT_UNGATED`) rather
than failing closed, because the shared-edge concern applies only to flows that
actually speak the protocol, and a non-TLS service on `:8443` is the same
L4-governed residual as `ssh.github.com:22`. **UDP alternate ports are
deliberately not covered**: the QUIC walk fails closed on an uncertain datagram
in every flow state, and softening that per-port would carve a hole in the
invariant rather than close one. HTTP/3 on an alternate port stays L4-only.

## Per-IP binding (`--tls-sni=enforce-pinned`)

Name matching alone answers "is this name allowed *somewhere*", which makes an
allowed name a **passphrase that opens every L7-scoped IP**: an attacker with a
server at any scoped address — reached via a broad CIDR, an auto-added infra
allow, or a stale allowlist entry — connects presenting an allowed SNI, their
own server ignores it, and the flow is admitted. This dimension additionally
requires the presented name to be one this daemon *saw resolve to that
destination* (`Manager.NameResolvedToIP`, fed by `RecordForwardResolution` and
CNAME-chain hops). Forging that means making a legitimate name
**forward-resolve** to the attacker's address through our proxy — DNS
hijacking, a far higher bar than owning a tenant on a shared edge.

**Only forward resolution is evidence.** Reverse DNS is excluded:
`UpdateDNSMapping` is also called with names recovered from PTR lookups
(`resolveDestination`'s lazy `LookupAddr`, the startup sweep, `ForwardMatchIP`
attribution), and a PTR record is controlled by whoever holds the destination
IP. Had those seeded the store, an attacker could set `PTR(their-IP) =
allowed.example`, let the blocked-event pipeline late-allow and scope their own
address, and then be admitted under that SNI — forging the binding with a record
they already own. PTR names still drive display attribution; they never mint
binding evidence.

**Scope iff bound.** `dns.RegisterL7Identity` is the only writer of
`map_l7_scope` and refuses to scope an IP the binding store cannot vouch for.
So an IP is L7-scoped *because* a name forward-resolved to it, and every
destination the matcher sees has a non-empty binding set — by construction,
not by every caller remembering. The cost is the honest residual: **a
destination we cannot bind stays L4-governed.** Startup pre-population
therefore records its Phase-1 answers as forward resolutions — they are forward
lookups of rule names through the system resolver, the same evidence class as
the proxy's own answers — rather than leaving IPs live processes already use
un-scopeable.

**Lifecycle.** The store is count-bounded LRU with refresh-on-use, deliberately
not TTL-swept: the L4 and `map_l7_scope` entries it gates never expire, so an
evidence-only expiry would deadlock a long-lived cached-IP client into a
`name_not_at_ip` deny it cannot self-heal (nothing re-resolves, so nothing
re-records). The caps also bound the many-names-to-one-edge shape this feature
targets, so DNS queries under a wildcard allow cannot grow the store without
limit.

The remaining gap is a client that reached an address our proxy never saw for
that name, so the dimension is **always measured and separately gated**: with
`--tls-sni=observe` or `=enforce` it reports `l7_would_block` with reason
`name_not_at_ip` and drops nothing. That rate is what decides whether
`=enforce-pinned` is safe to enable; enabling it only turns the would-narrow
outcome into a deny.

## Residual risk, stated honestly

This pins *which* name a flow reaches, never *what* is sent there. Open by
construction:

- **Exfil to a genuinely allowed origin** (a gist, a registry, a telemetry
  endpoint the run allows). The same class as the cross-step DNS channel
  design.md concedes: the verdict sees destination identity, not intent.
- **Wildcard and CNAME allows admit every name under them**, including names
  the operator does not control — the shape to weigh before writing a rule over
  a provider's shared domain, and the reason the infra auto-allow set is worth
  reading. L7 adds nothing over L4 here, and neither does the per-IP binding,
  since whoever owns such a name owns its DNS. Narrowing it needs
  provider-account binding, not a destination check.
- **Client-supplied ECH** to an ECH-enabled edge also fronting an allowed name:
  the inner SNI is invisible on the wire. Stripping DNS ECH configs only stops
  honest clients; there is no wire-layer defense. Accepted, not scheduled.
- **The datapath admits a flow, not the bytes it adjudicated.** Under enforce
  the adjudicated first flight is dropped; what reaches the destination is the
  retransmit, admitted on flow state without re-parsing (re-parsing would drop
  the connection's only copies forever). The guarantee is therefore over the
  flow's adjudicated identity, not over every byte later delivered on it. Not
  closable within drop-and-punt: verifying the admitted bytes
  means hashing the whole flight in-kernel, a per-byte loop the verifier
  rejects at these sizes, and `cgroup_skb` cannot buffer and reinject. It costs
  a *deliberately malicious* client, so L7 still holds against the
  misconfiguration and shared-edge cases it was built for, and observe mode is
  unaffected. Closing it needs a terminating proxy, which this design is not.
- **Non-TLS on 443, no-SNI clients, HTTP/1.0 without Host**: fail closed. See
  Ports above for what is and is not governed.
- **Versions the decryptor lacks, at an edge that supports them.** The walk
  tolerates an unskippable packet behind a found Initial so real clients can
  grease with a reserved-version trailer, which means it cannot distinguish
  that grease from a genuine future-version Initial. Closing it would forbid
  greasing or require decrypting versions we do not support. A datagram of such
  a version on its own is still refused outright, and the gap shrinks as the
  version table tracks deployed versions.

**Revisit only with a new mechanism**: provider-account binding, or in-kernel
QUIC-Initial parsing to drop the userspace round trip. No credible defense
against client-supplied ECH is currently known.
