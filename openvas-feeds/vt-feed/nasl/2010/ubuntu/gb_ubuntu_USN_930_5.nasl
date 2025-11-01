# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840465");
  script_cve_id("CVE-2008-5913", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1214");
  script_tag(name:"creation_date", value:"2010-07-26 14:14:51 +0000 (Mon, 26 Jul 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-930-5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-930-5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-930-5");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/599954");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ant, apturl, epiphany-browser, gluezilla, gnome-python-extras, liferea, mozvoikko, openjdk-6, packagekit, ubufox, webfav, yelp' package(s) announced via the USN-930-5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-930-4 fixed vulnerabilities in Firefox and Xulrunner on Ubuntu 9.04 and
9.10. This update provides updated packages for use with Firefox 3.6 and
Xulrunner 1.9.2.

Original advisory details:

 If was discovered that Firefox could be made to access freed memory. If a
 user were tricked into viewing a malicious site, a remote attacker could
 cause a denial of service or possibly execute arbitrary code with the
 privileges of the user invoking the program. This issue only affected
 Ubuntu 8.04 LTS. (CVE-2010-1121)

 Several flaws were discovered in the browser engine of Firefox. If a
 user were tricked into viewing a malicious site, a remote attacker could
 cause a denial of service or possibly execute arbitrary code with the
 privileges of the user invoking the program. (CVE-2010-1200, CVE-2010-1201,
 CVE-2010-1202, CVE-2010-1203)

 A flaw was discovered in the way plugin instances interacted. An attacker
 could potentially exploit this and use one plugin to access freed memory from a
 second plugin to execute arbitrary code with the privileges of the user
 invoking the program. (CVE-2010-1198)

 An integer overflow was discovered in Firefox. If a user were tricked into
 viewing a malicious site, an attacker could overflow a buffer and cause a
 denial of service or possibly execute arbitrary code with the privileges of
 the user invoking the program. (CVE-2010-1196)

 Martin Barbella discovered an integer overflow in an XSLT node sorting
 routine. An attacker could exploit this to overflow a buffer and cause a
 denial of service or possibly execute arbitrary code with the privileges of
 the user invoking the program. (CVE-2010-1199)

 Michal Zalewski discovered that the focus behavior of Firefox could be
 subverted. If a user were tricked into viewing a malicious site, a remote
 attacker could use this to capture keystrokes. (CVE-2010-1125)

 Ilja van Sprundel discovered that the 'Content-Disposition: attachment'
 HTTP header was ignored when 'Content-Type: multipart' was also present.
 Under certain circumstances, this could potentially lead to cross-site
 scripting attacks. (CVE-2010-1197)

 Amit Klein discovered that Firefox did not seed its random number generator
 often enough. An attacker could exploit this to identify and track users
 across different web sites. (CVE-2008-5913)

 Several flaws were discovered in the browser engine of Firefox. If a user
 were tricked into viewing a malicious site, a remote attacker could use
 this to crash the browser or possibly run arbitrary code as the user
 invoking the program. (CVE-2010-1208, CVE-2010-1209, CVE-2010-1211,
 CVE-2010-1212)

 An integer overflow was discovered in how Firefox processed plugin
 parameters. An attacker could exploit this to crash the browser or possibly
 run arbitrary code as the user invoking the program. (CVE-2010-1214)

 A flaw was discovered in the Firefox JavaScript engine. If a user were
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ant, apturl, epiphany-browser, gluezilla, gnome-python-extras, liferea, mozvoikko, openjdk-6, packagekit, ubufox, webfav, yelp' package(s) on Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
