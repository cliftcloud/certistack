# Getting help

Questions about CertiStack Community Edition go to GitHub Discussions, and bugs
to GitHub issues. There is no response-time commitment.

| I want to… | Go to |
| --- | --- |
| Get running for the first time | [Quickstart](docs/quickstart.md), then [going further](docs/going-further.md) |
| Understand an error or a failed run | [Troubleshooting](docs/troubleshooting.md) |
| Ask a how-to question or share lab results | [GitHub Discussions](https://github.com/cliftcloud/certistack/discussions) |
| Report a reproducible bug | [Open an issue](https://github.com/cliftcloud/certistack/issues/new/choose) (the template asks for the details we need) |
| Report a security vulnerability | **Privately**, as described in [SECURITY.md](SECURITY.md); never in a public issue |
| Get support beyond best effort, or the management daemon and dashboard | Support beyond best effort is agreed in a signed order ([commercial terms](https://certistack.dev/commercial-terms.html), section 7). See [certistack.dev](https://certistack.dev/#licensing) or write to sales@certistack.dev |

Before posting, run the failing command with `--debug`, note the output of
`certistack version` and your Proxmox VE/PBS versions, and remove credentials,
repository strings, private-key paths, and anything from a real customer
environment.
