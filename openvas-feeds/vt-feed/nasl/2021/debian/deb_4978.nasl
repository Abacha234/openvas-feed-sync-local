# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704978");
  script_cve_id("CVE-2020-16119", "CVE-2020-3702", "CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3679", "CVE-2021-3732", "CVE-2021-3739", "CVE-2021-3743", "CVE-2021-3753", "CVE-2021-37576", "CVE-2021-38160", "CVE-2021-38166", "CVE-2021-38199", "CVE-2021-40490", "CVE-2021-41073");
  script_tag(name:"creation_date", value:"2021-09-26 01:00:15 +0000 (Sun, 26 Sep 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 18:55:00 +0000 (Thu, 10 Mar 2022)");

  script_name("Debian: Security Advisory (DSA-4978)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4978");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4978");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4978 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2020-3702

A flaw was found in the driver for Atheros IEEE 802.11n family of chipsets (ath9k) allowing information disclosure.

CVE-2020-16119

Hadar Manor reported a use-after-free in the DCCP protocol implementation in the Linux kernel. A local attacker can take advantage of this flaw to cause a denial of service or potentially to execute arbitrary code.

CVE-2021-3653

Maxim Levitsky discovered a vulnerability in the KVM hypervisor implementation for AMD processors in the Linux kernel: Missing validation of the `int_ctl` VMCB field could allow a malicious L1 guest to enable AVIC support (Advanced Virtual Interrupt Controller) for the L2 guest. The L2 guest can take advantage of this flaw to write to a limited but still relatively large subset of the host physical memory.

CVE-2021-3656

Maxim Levitsky and Paolo Bonzini discovered a flaw in the KVM hypervisor implementation for AMD processors in the Linux kernel. Missing validation of the `virt_ext` VMCB field could allow a malicious L1 guest to disable both VMLOAD/VMSAVE intercepts and VLS (Virtual VMLOAD/VMSAVE) for the L2 guest. Under these circumstances, the L2 guest is able to run VMLOAD/VMSAVE unintercepted and thus read/write portions of the host's physical memory.

CVE-2021-3679

A flaw in the Linux kernel tracing module functionality could allow a privileged local user (with CAP_SYS_ADMIN capability) to cause a denial of service (resource starvation).

CVE-2021-3732

Alois Wohlschlager reported a flaw in the implementation of the overlayfs subsystem, allowing a local attacker with privileges to mount a filesystem to reveal files hidden in the original mount.

CVE-2021-3739

A NULL pointer dereference flaw was found in the btrfs filesystem, allowing a local attacker with CAP_SYS_ADMIN capabilities to cause a denial of service.

CVE-2021-3743

An out-of-bounds memory read was discovered in the Qualcomm IPC router protocol implementation, allowing to cause a denial of service or information leak.

CVE-2021-3753

Minh Yuan reported a race condition in the vt_k_ioctl in drivers/tty/vt/vt_ioctl.c, which may cause an out of bounds read in vt.

CVE-2021-37576

Alexey Kardashevskiy reported a buffer overflow in the KVM subsystem on the powerpc platform, which allows KVM guest OS users to cause memory corruption on the host.

CVE-2021-38160

A flaw in the virtio_console was discovered allowing data corruption or data loss by an untrusted device.

CVE-2021-38166

An integer overflow flaw in the BPF subsystem could allow a local attacker to cause a denial of service or potentially the execution of arbitrary code. This flaw is mitigated by default in Debian as unprivileged calls to bpf() are disabled.

CVE-2021-38199

Michael Wakabayashi reported a flaw in the NFSv4 client ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);