# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57477");
  script_cve_id("CVE-2004-2660", "CVE-2005-4798", "CVE-2006-1052", "CVE-2006-1343", "CVE-2006-1528", "CVE-2006-1855", "CVE-2006-1856", "CVE-2006-2444", "CVE-2006-2446", "CVE-2006-2935", "CVE-2006-2936", "CVE-2006-3468", "CVE-2006-3745", "CVE-2006-4093", "CVE-2006-4145", "CVE-2006-4535");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1184)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1184");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1184");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels, kernel-source-2.6.8' package(s) announced via the DSA-1184 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This advisory covers the S/390 components of the recent security update for the Linux 2.6.8 kernel that were missing due to technical problems. For reference, please see the text of the original advisory.

Several security related problems have been discovered in the Linux kernel which may lead to a denial of service or even the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2004-2660

Toshihiro Iwamoto discovered a memory leak in the handling of direct I/O writes that allows local users to cause a denial of service.

CVE-2005-4798

A buffer overflow in NFS readlink handling allows a malicious remote server to cause a denial of service.

CVE-2006-1052

Stephen Smalley discovered a bug in the SELinux ptrace handling that allows local users with ptrace permissions to change the tracer SID to the SID of another process.

CVE-2006-1343

Pavel Kankovsky discovered an information leak in the getsockopt system call which can be exploited by a local program to leak potentially sensitive memory to userspace.

CVE-2006-1528

Douglas Gilbert reported a bug in the sg driver that allows local users to cause a denial of service by performing direct I/O transfers from the sg driver to memory mapped I/O space.

CVE-2006-1855

Mattia Belletti noticed that certain debugging code left in the process management code could be exploited by a local attacker to cause a denial of service.

CVE-2006-1856

Kostik Belousov discovered a missing LSM file_permission check in the readv and writev functions which might allow attackers to bypass intended access restrictions.

CVE-2006-2444

Patrick McHardy discovered a bug in the SNMP NAT helper that allows remote attackers to cause a denial of service.

CVE-2006-2446

A race condition in the socket buffer handling allows remote attackers to cause a denial of service.

CVE-2006-2935

Diego Calleja Garcia discovered a buffer overflow in the DVD handling code that could be exploited by a specially crafted DVD USB storage device to execute arbitrary code.

CVE-2006-2936

A bug in the serial USB driver has been discovered that could be exploited by a custom made USB serial adapter to consume arbitrary amounts of memory.

CVE-2006-3468

James McKenzie discovered a denial of service vulnerability in the NFS driver. When exporting an ext3 file system over NFS, a remote attacker could exploit this to trigger a file system panic by sending a specially crafted UDP packet.

CVE-2006-3745

Wei Wang discovered a bug in the SCTP implementation that allows local users to cause a denial of service and possibly gain root privileges.

CVE-2006-4093

Olof Johansson discovered that the kernel does not disable the HID0 bit on PowerPC 970 processors which could be exploited by a local attacker to cause a denial of service.

CVE-2006-4145

A bug in the Universal Disk Format (UDF) filesystem driver could be ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'fai-kernels, kernel-source-2.6.8' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);