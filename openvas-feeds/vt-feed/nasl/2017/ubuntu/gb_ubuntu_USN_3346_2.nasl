# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843309");
  script_cve_id("CVE-2017-3142", "CVE-2017-3143");
  script_tag(name:"creation_date", value:"2017-09-19 05:42:15 +0000 (Tue, 19 Sep 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3346-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3346-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3346-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1717981");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-3346-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3346-1 fixed vulnerabilities in Bind. The fix for CVE-2017-3142
introduced a regression in the ability to receive an AXFR or IXFR in the
case where TSIG is used and not every message is signed. This update fixes
the problem.

In addition, this update adds the new root zone key signing key (KSK).

Original advisory details:

 Clement Berthaux discovered that Bind did not correctly check TSIG
 authentication for zone update requests. An attacker could use this
 to improperly perform zone updates. (CVE-2017-3143)

 Clement Berthaux discovered that Bind did not correctly check TSIG
 authentication for zone transfer requests. An attacker could use this
 to improperly transfer entire zones. (CVE-2017-3142)");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
