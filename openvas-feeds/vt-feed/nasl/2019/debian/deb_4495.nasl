# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704495");
  script_cve_id("CVE-2018-20836", "CVE-2019-10207", "CVE-2019-10638", "CVE-2019-1125", "CVE-2019-12817", "CVE-2019-12984", "CVE-2019-13233", "CVE-2019-13631", "CVE-2019-13648", "CVE-2019-14283", "CVE-2019-14284", "CVE-2019-1999");
  script_tag(name:"creation_date", value:"2019-08-12 02:00:28 +0000 (Mon, 12 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 02:22:00 +0000 (Thu, 03 Nov 2022)");

  script_name("Debian: Security Advisory (DSA-4495)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4495");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4495");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4495 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2018-20836

chenxiang reported a race condition in libsas, the kernel subsystem supporting Serial Attached SCSI (SAS) devices, which could lead to a use-after-free. It is not clear how this might be exploited.

CVE-2019-1125

It was discovered that most x86 processors could speculatively skip a conditional SWAPGS instruction used when entering the kernel from user mode, and/or could speculatively execute it when it should be skipped. This is a subtype of Spectre variant 1, which could allow local users to obtain sensitive information from the kernel or other processes. It has been mitigated by using memory barriers to limit speculative execution. Systems using an i386 kernel are not affected as the kernel does not use SWAPGS.

CVE-2019-1999

A race condition was discovered in the Android binder driver, which could lead to a use-after-free. If this driver is loaded, a local user might be able to use this for denial-of-service (memory corruption) or for privilege escalation.

CVE-2019-10207

The syzkaller tool found a potential null dereference in various drivers for UART-attached Bluetooth adapters. A local user with access to a pty device or other suitable tty device could use this for denial-of-service (BUG/oops).

CVE-2019-10638

Amit Klein and Benny Pinkas discovered that the generation of IP packet IDs used a weak hash function, jhash. This could enable tracking individual computers as they communicate with different remote servers and from different networks. The siphash function is now used instead.

CVE-2019-12817

It was discovered that on the PowerPC (ppc64el) architecture, the hash page table (HPT) code did not correctly handle fork() in a process with memory mapped at addresses above 512 TiB. This could lead to a use-after-free in the kernel, or unintended sharing of memory between user processes. A local user could use this for privilege escalation. Systems using the radix MMU, or a custom kernel with a 4 KiB page size, are not affected.

CVE-2019-12984

It was discovered that the NFC protocol implementation did not properly validate a netlink control message, potentially leading to a null pointer dereference. A local user on a system with an NFC interface could use this for denial-of-service (BUG/oops).

CVE-2019-13233

Jann Horn discovered a race condition on the x86 architecture, in use of the LDT. This could lead to a use-after-free. A local user could possibly use this for denial-of-service.

CVE-2019-13631

It was discovered that the gtco driver for USB input tablets could overrun a stack buffer with constant data while parsing the device's descriptor. A physically present user with a specially constructed USB device could use this to cause a denial-of-service (BUG/oops), or possibly for privilege ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);