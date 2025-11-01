# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841335");
  script_cve_id("CVE-2013-0871", "CVE-2013-1774", "CVE-2013-2058");
  script_tag(name:"creation_date", value:"2013-03-01 05:38:08 +0000 (Fri, 01 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1744-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1744-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1744-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1744-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Suleiman Souhlal, Salman Qazi, Aaron Durbin and Michael Davidson discovered
a race condition in the Linux kernel's ptrace syscall. An unprivileged
local attacker could exploit this flaw to run programs as an administrator.
(CVE-2013-0871)

A flaw was discovered in the Edgeort USB serial converter driver when the
device is disconnected while it is in use. A local user could exploit this
flaw to cause a denial of service (system crash). (CVE-2013-1774)

A flaw was discovered in the ChipIdea Highspeed Dual Role and ChipIdea host
controller drivers in the Linux kernel. A local user could use this flaw to
cause a denial of service (system crash). (CVE-2013-2058)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
