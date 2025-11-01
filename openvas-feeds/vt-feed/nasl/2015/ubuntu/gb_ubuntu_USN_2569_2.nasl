# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842170");
  script_tag(name:"creation_date", value:"2015-04-17 05:09:13 +0000 (Fri, 17 Apr 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2569-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2569-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2569-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1444518");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apport' package(s) announced via the USN-2569-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2569-1 fixed a vulnerability in Apport. Tavis Ormandy discovered that
the fixed packages were still vulnerable to a privilege escalation attack.
This update completely disables crash report handling for containers until
a more complete solution is available.

Original advisory details:

 Stephane Graber and Tavis Ormandy independently discovered that Apport
 incorrectly handled the crash reporting feature. A local attacker could use
 this issue to gain elevated privileges.");

  script_tag(name:"affected", value:"'apport' package(s) on Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
