# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841475");
  script_cve_id("CVE-2013-1798", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235");
  script_tag(name:"creation_date", value:"2013-06-18 05:11:44 +0000 (Tue, 18 Jun 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1876-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1876-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1876-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1876-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrew Honig reported a flaw in the way KVM (Kernel-based Virtual Machine)
emulated the IOAPIC. A privileged guest user could exploit this flaw to
read host memory or cause a denial of service (crash the host).
(CVE-2013-1798)

An information leak was discovered in the Linux kernel's rcvmsg path for
ATM (Asynchronous Transfer Mode). A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack memory.
(CVE-2013-3222)

An information leak was discovered in the Linux kernel's recvmsg path for
ax25 address family. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3223)

An information leak was discovered in the Linux kernel's recvmsg path for
the bluetooth address family. A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack memory.
(CVE-2013-3224)

An information leak was discovered in the Linux kernel's bluetooth rfcomm
protocol support. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3225)

An information leak was discovered in the Linux kernel's IRDA (infrared)
support subsystem. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3228)

An information leak was discovered in the Linux kernel's s390 - z/VM
support. A local user could exploit this flaw to examine potentially
sensitive information from the kernel's stack memory. (CVE-2013-3229)

An information leak was discovered in the Linux kernel's llc (Logical Link
Layer 2) support. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3231)

An information leak was discovered in the Linux kernel's receive message
handling for the netrom address family. A local user could exploit this
flaw to obtain sensitive information from the kernel's stack memory.
(CVE-2013-3232)

An information leak was discovered in the Linux kernel's Rose X.25 protocol
layer. A local user could exploit this flaw to examine potentially
sensitive information from the kernel's stack memory. (CVE-2013-3234)

An information leak was discovered in the Linux kernel's TIPC (Transparent
Inter Process Communication) protocol implementation. A local user could
exploit this flaw to examine potentially sensitive information from the
kernel's stack memory. (CVE-2013-3235)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
