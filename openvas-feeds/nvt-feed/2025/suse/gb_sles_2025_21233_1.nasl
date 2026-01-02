# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21233.1");
  script_cve_id("CVE-2025-11234", "CVE-2025-12464");
  script_tag(name:"creation_date", value:"2025-12-25 04:26:35 +0000 (Thu, 25 Dec 2025)");
  script_version("2026-01-01T05:49:19+0000");
  script_tag(name:"last_modification", value:"2026-01-01 05:49:19 +0000 (Thu, 01 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-03 11:15:30 +0000 (Fri, 03 Oct 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21233-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21233-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521233-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254494");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023642.html");
  script_xref(name:"URL", value:"https://lore.kernel.org/qemu-devel/1759986125.676506.643525.nullmailer@tls.msk.ru/");
  script_xref(name:"URL", value:"https://lore.kernel.org/qemu-devel/1761022287.744330.6357.nullmailer@tls.msk.ru/");
  script_xref(name:"URL", value:"https://lore.kernel.org/qemu-devel/1765037524.347582.2700543.nullmailer@tls.msk.ru/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2025:21233-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

Update to version 10.0.7.

Security issues fixed:

- CVE-2025-12464: stack-based buffer overflow in the e1000 network device operations can be exploited by a malicious
 guest user to crash the QEMU process on the host (bsc#1253002).
- CVE-2025-11234: use-after-free in WebSocket handshake operations can be exploited by a malicious client with network
 access to the VNC WebSocket port to cause a denial-of-service (bsc#1250984).

Other updates and bugfixes:

- Version 10.0.7:
 * kvm: Fix kvm_vm_ioctl() and kvm_device_ioctl() return value
 * docs/devel: Update URL for make-pullreq script
 * target/arm: Fix assert on BRA.
 * hw/aspeed/{xdma, rtc, sdhci}: Fix endianness to DEVICE_LITTLE_ENDIAN
 * hw/core/machine: Provide a description for aux-ram-share property
 * hw/pci: Make msix_init take a uint32_t for nentries
 * block/io_uring: avoid potentially getting stuck after resubmit at the end of ioq_submit()
 * block-backend: Fix race when resuming queued requests
 * ui/vnc: Fix qemu abort when query vnc info
 * chardev/char-pty: Do not ignore chr_write() failures
 * hw/display/exynos4210_fimd: Account for zero length in fimd_update_memory_section()
 * hw/arm/armv7m: Disable reentrancy guard for v7m_sysreg_ns_ops MRs
 * hw/arm/aspeed: Fix missing SPI IRQ connection causing DMA interrupt failure
 * migration: Fix transition to COLO state from precopy
 * Full backport list: [link moved to references]

- Version 10.0.6:
 * linux-user/microblaze: Fix little-endianness binary
 * target/hppa: correct size bit parity for fmpyadd
 * target/i386: user: do not set up a valid LDT on reset
 * async: access bottom half flags with qatomic_read
 * target/i386: fix x86_64 pushw op
 * i386/tcg/smm_helper: Properly apply DR values on SMM entry / exit
 * i386/cpu: Prevent delivering SIPI during SMM in TCG mode
 * i386/kvm: Expose ARCH_CAP_FB_CLEAR when invulnerable to MDS
 * target/i386: Fix CR2 handling for non-canonical addresses
 * block/curl.c: Use explicit long constants in curl_easy_setopt calls
 * pcie_sriov: Fix broken MMIO accesses from SR-IOV VFs
 * target/riscv: rvv: Fix vslide1[up<pipe>down].vx unexpected result when XLEN2 and SEWd
 * target/riscv: Fix ssamoswap error handling
 * Full backport list: [link moved to references]

- Version 10.0.5:
 * tests/functional/test_aarch64_sbsaref_freebsd: Fix the URL of the ISO image
 * tests/functional/test_ppc_bamboo: Replace broken link with working assets
 * physmem: Destroy all CPU AddressSpaces on unrealize
 * memory: New AS helper to serialize destroy+free
 * include/system/memory.h: Clarify address_space_destroy() behaviour
 * migration: Fix state transition in postcopy_start() error handling
 * target/riscv: rvv: Modify minimum VLEN according to enabled vector extensions
 * target/riscv: rvv: Replace checking V by checking Zve32x
 * target/riscv: Fix endianness swap on compressed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP applications 16.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-SLOF", rpm:"qemu-SLOF~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa", rpm:"qemu-audio-alsa~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-dbus", rpm:"qemu-audio-dbus~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-jack", rpm:"qemu-audio-jack~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-oss", rpm:"qemu-audio-oss~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-dmg", rpm:"qemu-block-dmg~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-nfs", rpm:"qemu-block-nfs~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-doc", rpm:"qemu-doc~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-extra", rpm:"qemu-extra~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-headless", rpm:"qemu-headless~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-gpu", rpm:"qemu-hw-display-virtio-gpu~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-gpu-pci", rpm:"qemu-hw-display-virtio-gpu-pci~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-vga", rpm:"qemu-hw-display-virtio-vga~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-s390x-virtio-gpu-ccw", rpm:"qemu-hw-s390x-virtio-gpu-ccw~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-usb-host", rpm:"qemu-hw-usb-host~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-usb-redirect", rpm:"qemu-hw-usb-redirect~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-usb-smartcard", rpm:"qemu-hw-usb-smartcard~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ivshmem-tools", rpm:"qemu-ivshmem-tools~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ksm", rpm:"qemu-ksm~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-linux-user", rpm:"qemu-linux-user~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-microvm", rpm:"qemu-microvm~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-pr-helper", rpm:"qemu-pr-helper~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390x", rpm:"qemu-s390x~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~10.0.71.16.3_3_g3d33c746~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-skiboot", rpm:"qemu-skiboot~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~10.0.71.16.3_3_g3d33c746~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vhost-user-gpu", rpm:"qemu-vhost-user-gpu~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vmsr-helper", rpm:"qemu-vmsr-helper~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~10.0.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
