# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841087");
  script_cve_id("CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960");
  script_tag(name:"creation_date", value:"2012-07-19 05:15:15 +0000 (Thu, 19 Jul 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1509-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1509-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1509-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1024562");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ubufox' package(s) announced via the USN-1509-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1509-1 fixed vulnerabilities in Firefox. This update provides an updated
ubufox package for use with the latest Firefox.

Original advisory details:

 Benoit Jacob, Jesse Ruderman, Christian Holler, Bill McCloskey, Brian Smith,
 Gary Kwong, Christoph Diehl, Chris Jones, Brad Lassey, and Kyle Huey discovered
 memory safety issues affecting Firefox. If the user were tricked into opening a
 specially crafted page, an attacker could possibly exploit these to cause a
 denial of service via application crash, or potentially execute code with the
 privileges of the user invoking Firefox. (CVE-2012-1948, CVE-2012-1949)

 Mario Gomes discovered that the address bar may be incorrectly updated.
 Drag-and-drop events in the address bar may cause the address of the previous
 site to be displayed while a new page is loaded. An attacker could exploit this
 to conduct phishing attacks. (CVE-2012-1950)

 Abhishek Arya discovered four memory safety issues affecting Firefox. If the
 user were tricked into opening a specially crafted page, an attacker could
 possibly exploit these to cause a denial of service via application crash, or
 potentially execute code with the privileges of the user invoking Firefox.
 (CVE-2012-1951, CVE-2012-1952, CVE-2012-1953, CVE-2012-1954)

 Mariusz Mlynski discovered that the address bar may be incorrectly updated.
 Calls to history.forward and history.back could be used to navigate to a site
 while the address bar still displayed the previous site. A remote attacker
 could exploit this to conduct phishing attacks. (CVE-2012-1955)

 Mario Heiderich discovered that HTML <embed> tags were not filtered out of the
 HTML <description> of RSS feeds. A remote attacker could exploit this to
 conduct cross-site scripting (XSS) attacks via javascript execution in the HTML
 feed view. (CVE-2012-1957)

 Arthur Gerkis discovered a use-after-free vulnerability. If the user were
 tricked into opening a specially crafted page, an attacker could possibly
 exploit this to cause a denial of service via application crash, or potentially
 execute code with the privileges of the user invoking Firefox. (CVE-2012-1958)

 Bobby Holley discovered that same-compartment security wrappers (SCSW) could be
 bypassed to allow XBL access. If the user were tricked into opening a specially
 crafted page, an attacker could possibly exploit this to execute code with the
 privileges of the user invoking Firefox. (CVE-2012-1959)

 Tony Payne discovered an out-of-bounds memory read in Mozilla's color
 management library (QCMS). If the user were tricked into opening a specially
 crafted color profile, an attacker could possibly exploit this to cause a
 denial of service via application crash. (CVE-2012-1960)

 Frederic Buclin discovered that the X-Frame-Options header was ignored when its
 value was specified multiple times. An attacker could exploit this to conduct
 clickjacking attacks. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ubufox' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
