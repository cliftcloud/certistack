# FAQ

Short answers. Each links to the page with the detail.

## What it does

### Why not just use PBS verify jobs?

PBS verify checks that the stored data is intact. It doesn't boot anything, so it can't tell you
that the VM starts or that its services come up. CertiStack does that, the same way every time, and
keeps a report of each run. Keep your verify jobs too: the two check different things.

### Does it change my backups or my VMs?

No. Backups are mapped read-only, and the sandbox is a new VM whose writes go to a throwaway
overlay. A run does make temporary changes on the node; [What it changes on your
node](what-it-changes.md) lists all of them.

### Does a pass mean my application works?

It means the probes in your plan passed in an isolated sandbox. A `tcp` probe proves a port is
open, and an `http` probe proves a status code. Pick probes for what each VM is for
([Going further](going-further.md#check-your-real-services)). A pass records one run; it is not a
certification.

### What if a backup contains malware?

The restored VM is isolated. The sandbox network has no gateway or uplink, and the worker's
firewall drops new traffic from it to the node. CertiStack doesn't scan for malware, but a VM whose
files were encrypted fails its probes, and the report records that.

### Is there a web UI, or a PDF report?

Not in the Community Edition. It is a command-line tool that writes a JSON report and shows it in
the terminal (`certistack report show`). The Enterprise Edition adds a dashboard and signed reports
([Editions](editions.md)).

## Will it work for me?

### Which versions are supported?

Proxmox VE 9.x and 8.4, each with PBS 3.x or 4.x, on amd64. Other PVE 8 releases run with a
warning; PVE 7 and PBS 2 are refused ([supported versions](compatibility.md#supported-versions)).

### Single node, ZFS, Ceph, containers?

- **A single node:** yes, and it's the simplest setup. The controller can be a VM on that node
  (not the Proxmox VE host itself).
- **ZFS, LVM-thin, Ceph:** the storage your VMs live on doesn't matter, because CertiStack restores
  from PBS. Only the overlay storage must be file-based, and setup creates one.
- **LXC containers:** not supported. Only VM backups are listed. `validate` refuses a `ct/` snapshot in a plan, and `plan` and `run` refuse a container's backup that sits under `vm/` ([Issue 46](troubleshooting.md#issue-46-a-backup-is-refused-before-the-run-starts)).

### How much time, memory and disk does a run need?

In the author's lab the median single-VM run took 12 minutes, and a small 12 GiB VM about six.
A run reads every byte of each disk once, so disk size and PBS read speed decide most of the time.
The node needs the VM's memory plus 256 MiB free, and disk space on the overlay storage
([how much](what-it-changes.md#things-to-plan-around)); timings are in
[Tested and supported](compatibility.md#how-long-a-run-takes).

### Can it test encrypted backups, or an older backup?

Yes to both ([Going further](going-further.md)).

## Running it

### Does it need root?

On the node, yes: mapping a backup needs root, so the controller logs in to the node as root over
SSH. The controller itself runs as an ordinary user
([what that key can do](what-it-changes.md#the-access-you-grant-and-what-limits-it)).

### Can I run it every night, and get alerted when it fails?

Yes, with a systemd timer or cron. A failed run exits non-zero, which can trigger email, ntfy, a
webhook or your monitoring ([Run it on a schedule](automation.md)).

### Can two runs happen at once?

Not on the same node: each node runs one CertiStack operation at a time. Runs on different nodes
can overlap if their plans use different sandbox VM IDs and network names.

### What if a run is interrupted?

The node keeps a journal of everything the run created. The next run on that node cleans it up
first, and `certistack recover` does it on demand ([When something fails](troubleshooting.md)).

### Where are reports kept?

On the controller, in `/var/lib/certistack/reports/<plan>/`, unless you chose another directory.
CertiStack never deletes them ([Reports](reports.md)).

### Does it send data anywhere?

No. It talks only to your PVE, PBS and node, and to the guests in the sandbox. The one exception is
off by default and opt-in: anonymous usage statistics, five fields at most once a day, however it was turned on, including `CERTISTACK_TELEMETRY=1`
([Usage statistics](telemetry.md)).

### How do I upgrade, or remove it?

See [Upgrade](going-further.md#upgrade). To remove it, follow [Remove CertiStack](undo.md).

## Licence and help

### What licence is it under? Can an MSP use it?

AGPL-3.0-or-later, with no limit on nodes or VMs. Commercial use is allowed, including by MSPs for
any number of clients. The AGPL's source obligations apply only if you distribute CertiStack, or
let others use a changed version of it over a network
([licensing FAQ](https://github.com/cliftcloud/certistack/blob/main/LICENSING-FAQ.md)). If your
policy rules out AGPL software, the Enterprise Edition comes with a commercial licence
([Editions](editions.md)).

### Where do I get help?

Ask in [GitHub Discussions](https://github.com/cliftcloud/certistack/discussions), and report bugs
as [issues](https://github.com/cliftcloud/certistack/issues/new/choose). Include the `--debug`
output, `certistack version` and your PVE and PBS versions, with credentials removed. Report a
security problem privately, as the
[security policy](https://github.com/cliftcloud/certistack/blob/main/SECURITY.md) says.
