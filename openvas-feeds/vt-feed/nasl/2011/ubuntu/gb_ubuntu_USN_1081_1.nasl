# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840599");
  script_cve_id("CVE-2010-3698", "CVE-2010-3865", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4079", "CVE-2010-4083", "CVE-2010-4248", "CVE-2010-4250", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4527", "CVE-2010-4648", "CVE-2010-4649", "CVE-2010-4650", "CVE-2011-0006", "CVE-2011-1044", "CVE-2011-4621");
  script_tag(name:"creation_date", value:"2011-03-07 05:45:55 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-08 15:19:00 +0000 (Tue, 08 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-1081-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1081-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1081-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1081-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that KVM did not correctly initialize certain CPU
registers. A local attacker could exploit this to crash the system, leading
to a denial of service. (CVE-2010-3698)

Thomas Pollet discovered that the RDS network protocol did not check
certain iovec buffers. A local attacker could exploit this to crash the
system or possibly execute arbitrary code as the root user. (CVE-2010-3865)

Vasiliy Kulikov discovered that the Linux kernel X.25 implementation did
not correctly clear kernel memory. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy. (CVE-2010-3875)

Vasiliy Kulikov discovered that the Linux kernel sockets implementation did
not properly initialize certain structures. A local attacker could exploit
this to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3876)

Vasiliy Kulikov discovered that the TIPC interface did not correctly
initialize certain structures. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-3877)

Nelson Elhage discovered that the Linux kernel IPv4 implementation did not
properly audit certain bytecodes in netlink messages. A local attacker
could exploit this to cause the kernel to hang, leading to a denial of
service. (CVE-2010-3880)

Dan Rosenberg discovered that the ivtv V4L driver did not correctly
initialize certain structures. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4079)

Dan Rosenberg discovered that the semctl syscall did not correctly clear
kernel memory. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-4083)

It was discovered that multithreaded exec did not handle CPU timers
correctly. A local attacker could exploit this to crash the system, leading
to a denial of service. (CVE-2010-4248)

Vegard Nossum discovered a leak in the kernel's inotify_init() system call.
A local, unprivileged user could exploit this to cause a denial of service.
(CVE-2010-4250)

Nelson Elhage discovered that Econet did not correctly handle AUN packets
over UDP. A local attacker could send specially crafted traffic to crash
the system, leading to a denial of service. (CVE-2010-4342)

Tavis Ormandy discovered that the install_special_mapping function could
bypass the mmap_min_addr restriction. A local attacker could exploit this
to mmap 4096 bytes below the mmap_min_addr area, possibly improving the
chances of performing NULL pointer dereference attacks. (CVE-2010-4346)

Dan Rosenberg discovered that the OSS subsystem did not handle name
termination correctly. A local attacker could exploit this crash the system
or gain root privileges. (CVE-2010-4527)

An error was reported in the kernel's ORiNOCO wireless driver's handling of
TKIP countermeasures. This reduces the amount of time an attacker needs
breach a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
