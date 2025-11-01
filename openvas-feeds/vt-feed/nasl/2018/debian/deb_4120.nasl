# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704120");
  script_cve_id("CVE-2017-13166", "CVE-2017-5754", "CVE-2018-5750");
  script_tag(name:"creation_date", value:"2018-02-21 23:00:00 +0000 (Wed, 21 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-05 11:31:00 +0000 (Tue, 05 May 2020)");

  script_name("Debian: Security Advisory (DSA-4120)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4120");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4120");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4120 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2017-5715

Multiple researchers have discovered a vulnerability in various processors supporting speculative execution, enabling an attacker controlling an unprivileged process to read memory from arbitrary addresses, including from the kernel and all other processes running on the system.

This specific attack has been named Spectre variant 2 (branch target injection) and is mitigated in the Linux kernel for the Intel x86-64 architecture by using the retpoline compiler feature which allows indirect branches to be isolated from speculative execution.

CVE-2017-5754

Multiple researchers have discovered a vulnerability in Intel processors, enabling an attacker controlling an unprivileged process to read memory from arbitrary addresses, including from the kernel and all other processes running on the system.

This specific attack has been named Meltdown and is addressed in the Linux kernel on the powerpc/ppc64el architectures by flushing the L1 data cache on exit from kernel mode to user mode (or from hypervisor to kernel).

This works on Power7, Power8 and Power9 processors.

CVE-2017-13166

A bug in the 32-bit compatibility layer of the v4l2 IOCTL handling code has been found. Memory protections ensuring user-provided buffers always point to userland memory were disabled, allowing destination address to be in kernel space. This bug could be exploited by an attacker to overwrite kernel memory from an unprivileged userland process, leading to privilege escalation.

CVE-2018-5750

An information leak has been found in the Linux kernel. The acpi_smbus_hc_add() prints a kernel address in the kernel log at every boot, which could be used by an attacker on the system to defeat kernel ASLR.

Additionally to those vulnerability, some mitigations for CVE-2017-5753 are included in this release.

CVE-2017-5753

Multiple researchers have discovered a vulnerability in various processors supporting speculative execution, enabling an attacker controlling an unprivileged process to read memory from arbitrary addresses, including from the kernel and all other processes running on the system.

This specific attack has been named Spectre variant 1 (bounds-check bypass) and is mitigated in the Linux kernel architecture by identifying vulnerable code sections (array bounds checking followed by array access) and replacing the array access with the speculation-safe array_index_nospec() function.

More use sites will be added over time.

For the stable distribution (stretch), these problems have been fixed in version 4.9.82-1+deb9u2.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);