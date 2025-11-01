# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892843");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-16119", "CVE-2020-3702", "CVE-2021-0920", "CVE-2021-20317", "CVE-2021-20321", "CVE-2021-20322", "CVE-2021-22543", "CVE-2021-3612", "CVE-2021-3653", "CVE-2021-3655", "CVE-2021-3679", "CVE-2021-37159", "CVE-2021-3732", "CVE-2021-3753", "CVE-2021-3760", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-38199", "CVE-2021-38204", "CVE-2021-38205", "CVE-2021-40490", "CVE-2021-41864", "CVE-2021-42008", "CVE-2021-42739", "CVE-2021-43389");
  script_tag(name:"creation_date", value:"2021-12-17 02:00:30 +0000 (Fri, 17 Dec 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-08 16:13:00 +0000 (Fri, 08 Oct 2021)");

  script_name("Debian: Security Advisory (DLA-2843)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2843");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2843");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-2843 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-3653 CVE-2021-3655 CVE-2021-3679 CVE-2021-3732 CVE-2021-3753 CVE-2021-3760 CVE-2021-20317 CVE-2021-20321 CVE-2021-20322 CVE-2021-22543 CVE-2021-37159 CVE-2021-38160 CVE-2021-38198 CVE-2021-38199 CVE-2021-38204 CVE-2021-38205 CVE-2021-40490 CVE-2021-41864 CVE-2021-42008 CVE-2021-42739 CVE-2021-43389

Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service, or information leaks.

CVE-2020-3702

A flaw was found in the driver for Atheros IEEE 802.11n family of chipsets (ath9k) allowing information disclosure.

CVE-2020-16119

Hadar Manor reported a use-after-free in the DCCP protocol implementation in the Linux kernel. A local attacker can take advantage of this flaw to cause a denial of service or potentially to execute arbitrary code.

CVE-2021-0920

A race condition was discovered in the local sockets (AF_UNIX) subsystem, which could lead to a use-after-free. A local user could exploit this for denial of service (memory corruption or crash), or possibly for privilege escalation.

CVE-2021-3612

Murray McAllister reported a flaw in the joystick input subsystem. A local user permitted to access a joystick device could exploit this to read and write out-of-bounds in the kernel, which could be used for privilege escalation.

CVE-2021-3653

Maxim Levitsky discovered a vulnerability in the KVM hypervisor implementation for AMD processors in the Linux kernel: Missing validation of the `int_ctl` VMCB field could allow a malicious L1 guest to enable AVIC support (Advanced Virtual Interrupt Controller) for the L2 guest. The L2 guest can take advantage of this flaw to write to a limited but still relatively large subset of the host physical memory.

CVE-2021-3655

Ilja Van Sprundel and Marcelo Ricardo Leitner found multiple flaws in the SCTP implementation, where missing validation could lead to an out-of-bounds read. On a system using SCTP, a networked attacker could exploit these to cause a denial of service (crash).

CVE-2021-3679

A flaw in the Linux kernel tracing module functionality could allow a privileged local user (with CAP_SYS_ADMIN capability) to cause a denial of service (resource starvation).

CVE-2021-3732

Alois Wohlschlager reported a flaw in the implementation of the overlayfs subsystem, allowing a local attacker with privileges to mount a filesystem to reveal files hidden in the original mount.

CVE-2021-3753

Minh Yuan reported a race condition in the vt_k_ioctl in drivers/tty/vt/vt_ioctl.c, which may cause an out of bounds read in vt.

CVE-2021-3760

Lin Horse reported a flaw in the NCI (NFC Controller Interface) driver, which could lead to a use-after-free.

However, this driver is not included in the binary packages provided by Debian.

CVE-2021-20317

It was discovered that the timer queue structure could become corrupt, leading to waiting tasks never being woken up. A local user ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);