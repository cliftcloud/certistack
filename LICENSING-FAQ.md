# Licensing FAQ

## Why the AGPL?

CertiStack runs restore tests against your Proxmox VE and PBS infrastructure, and the code that does that should stay
open to inspection and improvement by everyone who uses it, including a hosting provider or MSP that runs a modified
version as a service.

The GNU Affero General Public License, version 3 or any later version (AGPL-3.0-or-later), is an OSI-approved open
source license. You may use, modify and redistribute CertiStack. If you distribute it, you pass on the source under the
same license. If you run a modified version as a network service, you offer that service's users your modified source.

A permissive license (MIT, Apache 2.0) would let a provider build a competing hosted service on CertiStack without
contributing anything back. The AGPL prevents that without restricting private use, your own fork or your own on-premises
deployment.

## Can I use the Community Edition commercially?

Yes. The AGPL makes no distinction between commercial and non-commercial use: you can run CertiStack Community Edition
in a commercial environment, modify it, and build a paid service around it, as long as you comply with the license. In
practice: if others interact with your modified version over a network, you must make its source available to them
(Section 13 of the [AGPL](LICENSE)).

There is no capacity cap, VM limit or "non-commercial only" restriction.

## What if I can't comply with the AGPL's network clause?

A commercial license grants you rights to CertiStack with no copyleft obligation and no requirement to publish your
changes. It comes with the Enterprise Edition, the separately packaged management service, dashboard and HTTP API.

## Does the Enterprise Edition have to be open source too?

No. The Enterprise Edition is a separate, proprietary codebase. It is not part of this repository and is not licensed
under the AGPL. [Editions](https://certistack.dev/docs/editions/) lists what each edition includes.

## Where do I buy a commercial license?

The Enterprise Edition is in early access: write to sales@certistack.dev. Its license agreement is published before
checkout opens. Pricing is on [certistack.dev](https://certistack.dev/#licensing).
