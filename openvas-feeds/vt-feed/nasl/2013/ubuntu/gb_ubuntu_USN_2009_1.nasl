# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841612");
  script_cve_id("CVE-2013-1739", "CVE-2013-5590", "CVE-2013-5591", "CVE-2013-5592", "CVE-2013-5593", "CVE-2013-5595", "CVE-2013-5596", "CVE-2013-5597", "CVE-2013-5598", "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602", "CVE-2013-5603", "CVE-2013-5604");
  script_tag(name:"creation_date", value:"2013-11-08 05:26:22 +0000 (Fri, 08 Nov 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2009-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2009-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2009-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1245414");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2009-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted page, an attacker could possibly
exploit these to cause a denial of service via application crash, or
potentially execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2013-1739, CVE-2013-5590, CVE-2013-5591,
CVE-2013-5592)

Jordi Chancel discovered that HTML select elements could display arbitrary
content. An attacker could potentially exploit this to conduct
URL spoofing or clickjacking attacks (CVE-2013-5593)

Abhishek Arya discovered a crash when processing XSLT data in some
circumstances. An attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2013-5604)

Dan Gohman discovered a flaw in the Javascript engine. When combined
with other vulnerabilities, an attacked could possibly exploit this
to execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2013-5595)

Ezra Pool discovered a crash on extremely large pages. An attacked
could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-5596)

Byoungyoung Lee discovered a use-after-free when updating the offline
cache. An attacker could potentially exploit this to cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-5597)

Cody Crews discovered a way to append an iframe in to an embedded PDF
object displayed with PDF.js. An attacked could potentially exploit this
to read local files, leading to information disclosure. (CVE-2013-5598)

Multiple use-after-free flaws were discovered in Firefox. An attacker
could potentially exploit these to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2013-5599, CVE-2013-5600, CVE-2013-5601)

A memory corruption flaw was discovered in the Javascript engine when
using workers with direct proxies. An attacker could potentially exploit
this to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2013-5602)

Abhishek Arya discovered a use-after-free when interacting with HTML
document templates. An attacker could potentially exploit this to cause
a denial of service via application crash or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2013-5603)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
