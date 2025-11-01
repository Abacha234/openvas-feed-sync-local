# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842675");
  script_cve_id("CVE-2016-2512", "CVE-2016-2513");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:31 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2915-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2915-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2915-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1553251");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-2915-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2915-1 fixed vulnerabilities in Django. The upstream fix for
CVE-2016-2512 introduced a regression for certain applications. This update
fixes the problem by applying the complete upstream regression fix.

Original advisory details:

 Mark Striemer discovered that Django incorrectly handled user-supplied
 redirect URLs containing basic authentication credentials. A remote
 attacker could possibly use this issue to perform a cross-site scripting
 attack or a malicious redirect. (CVE-2016-2512)

 Sjoerd Job Postmus discovered that Django incorrectly handled timing when
 doing password hashing operations. A remote attacker could possibly use
 this issue to perform user enumeration. (CVE-2016-2513)");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
