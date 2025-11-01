# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840264");
  script_cve_id("CVE-2007-6282", "CVE-2007-6712", "CVE-2008-0598", "CVE-2008-1615", "CVE-2008-1673", "CVE-2008-2136", "CVE-2008-2137", "CVE-2008-2148", "CVE-2008-2358", "CVE-2008-2365", "CVE-2008-2729", "CVE-2008-2750", "CVE-2008-2826");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-625-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-625-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-625-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-source-2.6.15, linux-source-2.6.20, linux-source-2.6.22' package(s) announced via the USN-625-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dirk Nehring discovered that the IPsec protocol stack did not correctly
handle fragmented ESP packets. A remote attacker could exploit this to
crash the system, leading to a denial of service. (CVE-2007-6282)

Johannes Bauer discovered that the 64bit kernel did not correctly handle
hrtimer updates. A local attacker could request a large expiration value
and cause the system to hang, leading to a denial of service.
(CVE-2007-6712)

Tavis Ormandy discovered that the ia32 emulation under 64bit kernels did
not fully clear uninitialized data. A local attacker could read private
kernel memory, leading to a loss of privacy. (CVE-2008-0598)

Jan Kratochvil discovered that PTRACE did not correctly handle certain
calls when running under 64bit kernels. A local attacker could exploit this
to crash the system, leading to a denial of service. (CVE-2008-1615)

Wei Wang discovered that the ASN.1 decoding routines in CIFS and SNMP NAT
did not correctly handle certain length values. Remote attackers could
exploit this to execute arbitrary code or crash the system. (CVE-2008-1673)

Paul Marks discovered that the SIT interfaces did not correctly manage
allocated memory. A remote attacker could exploit this to fill all
available memory, leading to a denial of service. (CVE-2008-2136)

David Miller and Jan Lieskovsky discovered that the Sparc kernel did not
correctly range-check memory regions allocated with mmap. A local attacker
could exploit this to crash the system, leading to a denial of service.
(CVE-2008-2137)

The sys_utimensat system call did not correctly check file permissions in
certain situations. A local attacker could exploit this to modify the file
times of arbitrary files which could lead to a denial of service.
(CVE-2008-2148)

Brandon Edwards discovered that the DCCP system in the kernel did not
correctly check feature lengths. A remote attacker could exploit this to
execute arbitrary code. (CVE-2008-2358)

A race condition was discovered between ptrace and utrace in the kernel. A
local attacker could exploit this to crash the system, leading to a denial
of service. (CVE-2008-2365)

The copy_to_user routine in the kernel did not correctly clear memory
destination addresses when running on 64bit kernels. A local attacker could
exploit this to gain access to sensitive kernel memory, leading to a loss
of privacy. (CVE-2008-2729)

The PPP over L2TP routines in the kernel did not correctly handle certain
messages. A remote attacker could send a specially crafted packet that
could crash the system or execute arbitrary code. (CVE-2008-2750)

Gabriel Campana discovered that SCTP routines did not correctly check for
large addresses. A local user could exploit this to allocate all available
memory, leading to a denial of service. (CVE-2008-2826)");

  script_tag(name:"affected", value:"'linux, linux-source-2.6.15, linux-source-2.6.20, linux-source-2.6.22' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
