# CertiStack documentation {#certistack-community-edition-documentation}

CertiStack proves your Proxmox backups actually restore. It takes a VM's backup from Proxmox Backup
Server, boots it in an isolated sandbox on your Proxmox VE node, checks that its services answer,
removes everything again, and writes a report. Your backups are only read, and your VMs are never
touched.

**New here? Start with the [quickstart](quickstart.md).** It takes you from nothing to your first
report on one node.

## How a run works

1. The controller (a small Linux machine) connects to your Proxmox VE node over SSH.
2. The node maps the backup read-only and boots a copy of the VM on a throwaway overlay, in a
   network with no way out.
3. CertiStack checks what you asked it to: SSH, a web page, DNS, a directory, SQL Server, a file
   share.
4. It removes the VM, the overlay and the network, and checks that nothing is left.
5. It writes a report: pass or fail, what was checked, how long the restore took, and proof of the
   cleanup.

A run passes only when every check passed **and** the cleanup was verified. On the final v0.1.0
code, 24 restore tests ran on the author's own infrastructure and all passed
([what was tested](compatibility.md#what-was-tested)).

## Where to go next

| You want to | Read |
| --- | --- |
| Try it | [Quickstart](quickstart.md) |
| Know what it does to your node first | [What it changes on your node](what-it-changes.md) |
| Check real services, more VMs, a cluster | [Going further](going-further.md) |
| Run it every night | [Run it on a schedule](automation.md) |
| Fix an error | [When something fails](troubleshooting.md) |
| Look up a command, a plan key or a setting | [Commands](cli-reference.md), [The plan file](plan-reference.md), [Settings and files](configuration.md) |

[License](https://github.com/cliftcloud/certistack/blob/main/LICENSE) ·
[Security policy](https://github.com/cliftcloud/certistack/blob/main/SECURITY.md) ·
[Getting help](https://github.com/cliftcloud/certistack/blob/main/SUPPORT.md) ·
[Contributing](https://github.com/cliftcloud/certistack/blob/main/CONTRIBUTING.md)
