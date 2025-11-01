# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840579");
  script_cve_id("CVE-2010-0435", "CVE-2010-3859", "CVE-2010-3873", "CVE-2010-3874", "CVE-2010-3881", "CVE-2010-4073", "CVE-2010-4079", "CVE-2010-4083", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4175", "CVE-2010-4243", "CVE-2010-4249", "CVE-2010-4256", "CVE-2010-4258");
  script_tag(name:"creation_date", value:"2011-02-04 13:19:53 +0000 (Fri, 04 Feb 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1054-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1054-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1054-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-ec2' package(s) announced via the USN-1054-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gleb Napatov discovered that KVM did not correctly check certain privileged
operations. A local attacker with access to a guest kernel could exploit
this to crash the host system, leading to a denial of service.
(CVE-2010-0435)

Dan Rosenberg discovered that the Linux kernel TIPC implementation
contained multiple integer signedness errors. A local attacker could
exploit this to gain root privileges. (CVE-2010-3859)

Dan Rosenberg discovered that the Linux kernel X.25 implementation
incorrectly parsed facilities. A remote attacker could exploit this to
crash the kernel, leading to a denial of service. (CVE-2010-3873)

Dan Rosenberg discovered that the CAN protocol on 64bit systems did not
correctly calculate the size of certain buffers. A local attacker could
exploit this to crash the system or possibly execute arbitrary code as the
root user. (CVE-2010-3874)

Vasiliy Kulikov discovered that kvm did not correctly clear memory. A local
attacker could exploit this to read portions of the kernel stack, leading
to a loss of privacy. (CVE-2010-3881)

Dan Rosenberg discovered that IPC structures were not correctly initialized
on 64bit systems. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-4073)

Dan Rosenberg discovered that the ivtv V4L driver did not correctly
initialize certain structures. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4079)

Dan Rosenberg discovered that the semctl syscall did not correctly clear
kernel memory. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-4083)

Dan Rosenberg discovered that the socket filters did not correctly
initialize structure memory. A local attacker could create malicious
filters to read portions of kernel stack memory, leading to a loss of
privacy. (CVE-2010-4158)

Dan Rosenberg discovered that the Linux kernel L2TP implementation
contained multiple integer signedness errors. A local attacker could
exploit this to crash the kernel, or possibly gain root privileges.
(CVE-2010-4160)

Dan Rosenberg discovered that certain iovec operations did not calculate
page counts correctly. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4162)

Dan Rosenberg discovered multiple flaws in the X.25 facilities parsing. If
a system was using X.25, a remote attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4164)

Steve Chen discovered that setsockopt did not correctly check MSS values. A
local attacker could make a specially crafted socket call to crash the
system, leading to a denial of service. (CVE-2010-4165)

Dave Jones discovered that the mprotect system call did not correctly
handle merged VMAs. A local attacker could exploit this to crash the
system, leading to a denial of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-ec2' package(s) on Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
