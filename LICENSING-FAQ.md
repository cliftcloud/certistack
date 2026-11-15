# Licensing FAQ

## Why the AGPL?

CertiStack Community Edition runs restore tests against Proxmox VE and
PBS infrastructure, and we want the code that does that to stay
inspectable and improvable by everyone who uses it — including a hosting
provider or MSP who runs a modified version as a service. The GNU Affero General Public License, version 3 or any
later version (AGPL-3.0-or-later), is an OSI-approved open source license that lets you use, modify and
redistribute it. Its copyleft conditions apply when you distribute
CertiStack (pass on the source, under the same licence) and, the one the
AGPL adds, when you run a modified version as a network service (offer
that service's users your modified source).

That single condition is what a permissive license (MIT, Apache 2.0)
doesn't give us: without it, a hosting provider could take CertiStack,
build a competing hosted validation service on top of it, and never
contribute anything back — while we keep maintaining the upstream project
they depend on. The AGPL closes that gap without restricting what you can
do with your own private use, your own fork, or your own on-prem
deployment. It's a stronger commitment to openness than a
source-available license (which by definition isn't open source), not a
weaker one.

## Can I use CE commercially?

Yes. The AGPL does not distinguish between commercial and non-commercial
use — you can run CertiStack Community Edition in a commercial
environment, modify it, and even build a paid service around it, as long
as you comply with the license. In practice that mainly means: if your
service lets others interact with a modified version of CertiStack over
a network, you must make that modified version's source available to
them (Section 13 of the AGPL; see [LICENSE](LICENSE)).

There is no capacity cap, VM limit, or "non-commercial only" restriction.

## What if I can't comply with AGPL's network-copyleft clause?

Some organizations have policies against deploying AGPL software, or
want to build a hosted/managed offering on top of CertiStack without
being required to publish their modifications. If that's you, buy a
commercial license instead. It grants you rights to CertiStack under
standard commercial terms, with no copyleft obligation and no requirement
to publish your changes. A commercial license is delivered as a signed
entitlement for the separately packaged Enterprise Edition (the persistent
management daemon, dashboard, and HTTP API). The plans, what each includes,
and which of them allow commercial use are on the pricing page,
[certistack.dev/#licensing](https://certistack.dev/#licensing).

## Does the Enterprise Edition have to be open source too?

No. The Enterprise Edition is a separate, proprietary codebase that has
never been part of this repository and is not licensed under the AGPL. See
[docs/editions.md](docs/editions.md) for what each edition includes.

## Where do I buy a commercial license?

Contact sales@certistack.dev, or see the pricing section at
[certistack.dev/#licensing](https://certistack.dev/#licensing). The terms
that govern a purchase are the
[commercial license agreement](https://certistack.dev/commercial-terms.html).
