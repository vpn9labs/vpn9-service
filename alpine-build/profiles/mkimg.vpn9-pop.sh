# mkimg.pop.sh
# Custom profile for building a minimal Alpine ISO with VPN and networking support

profile_vpn9-pop() {
  # Basic profile metadata
  profile_standard
  title="Alpine Linux Pop Profile"
  desc="Minimal Alpine ISO with WireGuard and iptables support"
  arch="x86_64"
  kernel_flavors="lts" # Use the long-term support kernel
  hostname="vpn9-pop"
  # initrd_ucode="/boot/amd-ucode.tar /boot/intel-ucode.tar" # Optional: CPU microcode for broader hardware support

  # Packages to include in the ISO
  apks="$apks
        linux-lts
        wireguard-tools
        iptables
        iproute2
        openssh
        alpine-conf
        alpine-base
        syslinux
        haveged
        intel-ucode
        amd-ucode
        ifupdown-ng
        dhcpcd
        busybox-extras
        libgcc
        "

  # Kernel command-line parameters
  kernel_cmdline="quiet"

  # System services to enable
  sysinit="bootmisc hwclock modules sysctl hostname hwdrivers"
  services="networking sshd haveged"

  # Filesystem and initramfs settings
  initfs_cmdline="modules=loop,squashfs,sd-mod,usb-storage"
  apkovl="genapkovl-vpn9-pop.sh"
}
