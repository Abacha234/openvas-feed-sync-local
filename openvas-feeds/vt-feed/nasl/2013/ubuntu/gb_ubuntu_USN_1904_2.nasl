# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841503");
  script_cve_id("CVE-2013-0339", "CVE-2013-2877");
  script_tag(name:"creation_date", value:"2013-08-01 13:38:42 +0000 (Thu, 01 Aug 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1904-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1904-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1904-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1201849");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the USN-1904-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1904-1 fixed vulnerabilities in libxml2. The update caused a regression
for certain users. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that libxml2 would load XML external entities by default.
 If a user or automated system were tricked into opening a specially crafted
 document, an attacker could possibly obtain access to arbitrary files or
 cause resource consumption. This issue only affected Ubuntu 10.04 LTS,
 Ubuntu 12.04 LTS, and Ubuntu 12.10. (CVE-2013-0339)

 It was discovered that libxml2 incorrectly handled documents that end
 abruptly. If a user or automated system were tricked into opening a
 specially crafted document, an attacker could possibly cause libxml2 to
 crash, resulting in a denial of service. (CVE-2013-2877)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
