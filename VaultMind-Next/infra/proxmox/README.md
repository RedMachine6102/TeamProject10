# Proxmox deployment

## Current VM

VM `101` (`vaultmind-backend`) was created on node `pve` for the first working
deployment. It uses the existing Ubuntu 24.04.3 Server ISO and is configured
with:

- 2 vCPU (`x86-64-v2-AES`)
- 2 GB RAM
- 32 GB on `local-lvm`, with discard and an IO thread enabled
- VirtIO networking on `vmbr0`, with the Proxmox firewall enabled
- QEMU guest agent support
- automatic startup with the host

Ubuntu Server 24.04.4 LTS is installed and fully updated. The installer ISO is
detached, and a clean reboot was verified. Current DHCP address:
`192.168.30.114`, reserved in OPNsense.

Installed and verified services:

- OpenSSH, with UFW allowing only TCP port 22 inbound
- QEMU guest agent
- Docker 29.1.3 and Docker Compose 2.40.3
- unattended security upgrades
- VaultMind Next API and scheduler running as non-root Docker Compose services

The application is installed at `/home/vaultmind/vaultmind-next`. Its SQLite
database uses a named Docker volume, and persistence was verified across a
container restart. The scheduler automatically creates due rotation jobs.
Docker starts at boot and both services use the `unless-stopped` restart policy.
The application listens only on
`127.0.0.1:8080`; use an SSH tunnel for development or add a TLS reverse proxy
before allowing browser access from another host.

The administrator login is stored in Bitwarden as
`VaultMind Backend VM 101`; no credential is stored in this repository.

## Recommended first environment

- Ubuntu 24.04 LTS cloud image
- 2 vCPU, 2-4 GB RAM, 32-40 GB encrypted storage
- dedicated VLAN with inbound access only through a reverse proxy
- Secure Boot and virtual TPM when supported
- unattended security updates
- API bound to localhost; TLS terminated by Caddy or another managed proxy
- outbound traffic restricted to package mirrors and approved providers
- daily encrypted snapshots copied to separate storage

## Required values

```text
PROXMOX_API_URL=https://proxmox.example:8006/api2/json
PROXMOX_NODE=pve
PROXMOX_TOKEN_ID=vaultmind-deployer@pve!automation
PROXMOX_TOKEN_SECRET=stored-outside-git
PROXMOX_TEMPLATE=ubuntu-2404-cloudinit
PROXMOX_STORAGE=local-lvm
PROXMOX_BRIDGE=vmbr0
```

Use a dedicated API token limited to VM clone/configuration on the chosen node.
Do not use a root password or a token with cluster-wide permissions. Once these
values and the desired hostname/network are provided, the next step is a
reviewable OpenTofu module plus cloud-init, followed by a plan before apply.
