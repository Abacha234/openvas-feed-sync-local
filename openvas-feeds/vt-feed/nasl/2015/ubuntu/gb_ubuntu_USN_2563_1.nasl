# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842160");
  script_cve_id("CVE-2015-1421", "CVE-2015-1465", "CVE-2015-1593", "CVE-2015-2041", "CVE-2015-2042");
  script_tag(name:"creation_date", value:"2015-04-09 05:09:08 +0000 (Thu, 09 Apr 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2563-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2563-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2563-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2563-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sun Baoliang discovered a use after free flaw in the Linux kernel's SCTP
(Stream Control Transmission Protocol) subsystem during INIT collisions. A
remote attacker could exploit this flaw to cause a denial of service
(system crash) or potentially escalate their privileges on the system.
(CVE-2015-1421)

Marcelo Leitner discovered a flaw in the Linux kernel's routing of packets
to too many different dsts/too fast. A remote attacker on the same subnet can exploit this
flaw to cause a denial of service (system crash). (CVE-2015-1465)

An integer overflow was discovered in the stack randomization feature of
the Linux kernel on 64 bit platforms. A local attacker could exploit this
flaw to bypass the Address Space Layout Randomization (ASLR) protection
mechanism. (CVE-2015-1593)

An information leak was discovered in the Linux Kernel's handling of
userspace configuration of the link layer control (LLC). A local user could
exploit this flaw to read data from other sysctl settings. (CVE-2015-2041)

An information leak was discovered in how the Linux kernel handles setting
the Reliable Datagram Sockets (RDS) settings. A local user could exploit
this flaw to read data from other sysctl settings. (CVE-2015-2042)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
