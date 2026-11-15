// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"fmt"

	"github.com/cliftcloud/certistack/internal/macaddr"
	"github.com/cliftcloud/certistack/pkg/config"
)

// resolveNet0Identity gives the sandbox VM's net0 the identity the plan left
// open, from the backed-up net0 (sourceMAC and sourceModel, empty when the
// source has no usable net0): the plan's mac and nic_model win, and what it
// leaves empty is the source's.
//
// In network_recovery.mode preserve the guest is left exactly as it was
// backed up, so a network profile bound to the adapter (a NetworkManager or
// ifcfg HWADDR, a netplan or systemd-networkd match on the MAC, a Windows
// static adapter configuration) finds its NIC only if net0 keeps the source's
// MAC and model. Nothing rewrites the profile to follow a new identity there,
// as the other modes do in the disposable overlay. So preserve takes the
// source's identity when the plan leaves it out, whether or not the plan
// inherits the rest of the backup's configuration, and refuses a plan that
// replaces it, rather than start a guest that comes up without its NIC and
// report its services as down. The other modes let the plan choose.
func resolveNet0Identity(vm *config.VM, sourceMAC, sourceModel string) error {
	if vm.NetworkRecovery.EffectiveMode() == "preserve" {
		if vm.MAC != "" && sourceMAC != "" && !macaddr.Equal(vm.MAC, sourceMAC) {
			return fmt.Errorf("target VM %d (%s) keeps its guest's network as backed up (network_recovery.mode preserve), but its mac %s is not its backup's net0 MAC %s: a guest whose network configuration is bound to the adapter's MAC would not find its NIC, and nothing in this mode rewrites the guest. Remove mac to use the backup's, or set it to %s; a plan that gives the VM a new identity needs a mode that rewrites the guest's network (auto)", vm.VMID, vm.Name, vm.MAC, sourceMAC, sourceMAC)
		}
		if vm.NICModel != "" && sourceModel != "" && vm.NICModel != sourceModel {
			return fmt.Errorf("target VM %d (%s) keeps its guest's network as backed up (network_recovery.mode preserve), but its nic_model %s is not its backup's net0 model %s: the guest's driver and adapter binding follow the model. Remove nic_model to use the backup's, or set it to %s; a plan that changes the adapter needs a mode that rewrites the guest's network (auto)", vm.VMID, vm.Name, vm.NICModel, sourceModel, sourceModel)
		}
	}
	if vm.MAC == "" {
		vm.MAC = sourceMAC
	}
	if vm.NICModel == "" {
		vm.NICModel = sourceModel
	}
	return nil
}
