# Guided setup upgrade notes

See [Guided setup](guided-setup.md) for the operator walkthrough.

## Default means the unmatched-client fallback

During setup review, the policy engine was found to choose a CIDR-less fallback
by network name. A new token-only network named `AAA roaming laptop` could
therefore silently replace the `Default` network for unrelated unmatched clients.
If that new profile used Monitor only, ordinary clients could lose the filtering
policy they previously received. The source-access ACL and token authentication
are separate from this policy-attribution problem.

The engine now prefers the seeded `n_default` row whenever it is enabled and
CIDR-less, independently of its display name or its ad-hoc-access bit. Named
source prefixes still use longest-prefix matching, and token-identified clients
still use their selected network's policy. No network row, policy content,
credential or access grant is rewritten by this correction.

This is a deliberate attribution change for installations that previously
relied on an alphabetically earlier CIDR-less network to override an enabled,
CIDR-less Default. Put the desired unmatched-client policy on **Default** rather
than encoding that choice in alphabetical naming. When Default is absent,
disabled or has explicit CIDRs, the existing legacy fallback selection is
preserved. Keep the normal Default row enabled and CIDR-less when adding roaming
profiles; its resolver-access switch is a separate choice.

Regression tests create a Monitor-only roaming network before Default in name
order, verify that ordinary unmatched clients keep Standard filtering, and
verify that the roaming network retains its own token-selected policy. Renaming
Default must not change its fallback responsibility.

## The displayed DNS address is not proof of connectivity

Saved dashboard addresses are explicit operator configuration, with configuration
file/environment precedence. They do not prove that a listener, firewall, NAT,
VPN or HTTPS certificate is ready. Test from an intended client before changing
DHCP for an entire network. Starter files are not an in-place migration and do
not copy the current instance's network grants or tokens to a new installation.
