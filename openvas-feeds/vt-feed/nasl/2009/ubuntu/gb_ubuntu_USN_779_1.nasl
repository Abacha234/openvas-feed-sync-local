# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64261");
  script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841");
  script_tag(name:"creation_date", value:"2009-06-23 13:49:15 +0000 (Tue, 23 Jun 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-779-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-779-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-779-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox-3.0, xulrunner-1.9' package(s) announced via the USN-779-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several flaws were discovered in the browser and JavaScript engines of
Firefox. If a user were tricked into viewing a malicious website, a remote
attacker could cause a denial of service or possibly execute arbitrary code
with the privileges of the user invoking the program. (CVE-2009-1392,
CVE-2009-1832, CVE-2009-1833, CVE-2009-1837, CVE-2009-1838)

Pavel Cvrcek discovered that Firefox would sometimes display certain
invalid Unicode characters as whitespace. An attacker could exploit this to
spoof the location bar, such as in a phishing attack. (CVE-2009-1834)

Gregory Fleischer, Adam Barth and Collin Jackson discovered that Firefox
would allow access to local files from resources loaded via the file:
protocol. If a user were tricked into downloading then opening a malicious
file, an attacker could steal potentially sensitive information.
(CVE-2009-1835, CVE-2009-1839)

Shuo Chen, Ziqing Mao, Yi-Min Wang, and Ming Zhang discovered that Firefox
did not properly handle error responses when connecting to a proxy server.
If a remote attacker were able to perform a machine-in-the-middle attack, this
flaw could be exploited to view sensitive information. (CVE-2009-1836)

Wladimir Palant discovered Firefox did not check content-loading policies
when loading external script files into XUL documents. As a result, Firefox
might load malicious content under certain circumstances. (CVE-2009-1840)

It was discovered that Firefox could be made to run scripts with elevated
privileges. If a user were tricked into viewing a malicious website, an
attacker could cause a chrome privileged object, such as the browser
sidebar, to run arbitrary code via interactions with the attacker
controlled website. (CVE-2009-1841)");

  script_tag(name:"affected", value:"'firefox-3.0, xulrunner-1.9' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
