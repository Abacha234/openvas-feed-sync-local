# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841553");
  script_cve_id("CVE-2013-1718", "CVE-2013-1719", "CVE-2013-1720", "CVE-2013-1721", "CVE-2013-1722", "CVE-2013-1724", "CVE-2013-1725", "CVE-2013-1728", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737", "CVE-2013-1738");
  script_tag(name:"creation_date", value:"2013-09-18 04:43:03 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1951-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1951-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1951-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1223826");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-1951-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted page, an attacker could possibly
exploit these to cause a denial of service via application crash, or
potentially execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2013-1718, CVE-2013-1719)

Atte Kettunen discovered a flaw in the HTML5 Tree Builder when interacting
with template elements. In some circumstances, an attacker could
potentially exploit this to execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2013-1720)

Alex Chapman discovered an integer overflow vulnerability in the ANGLE
library. An attacker could potentially exploit this to execute arbitrary
code with the privileges of the user invoking Firefox. (CVE-2013-1721)

Abhishek Arya discovered a use-after-free in the Animation Manager. An
attacked could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-1722)

Scott Bell discovered a use-after-free when using a select element. An
attacker could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-1724)

It was discovered that the scope of new Javascript objects could be
accessed before their compartment is initialized. An attacker could
potentially exploit this to execute code with the privileges of the user
invoking Firefox. (CVE-2013-1725)

Dan Gohman discovered that some variables and data were used in IonMonkey,
without being initialized, which could lead to information leakage.
(CVE-2013-1728)

Sachin Shinde discovered a crash when moving some XBL-backed nodes
in to a document created by document.open(). An attacker could potentially
exploit this to cause a denial of service. (CVE-2013-1730)

Aki Helin discovered a buffer overflow when combining lists, floats and
multiple columns. An attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2013-1732)

Two memory corruption bugs when scrolling were discovered. An attacker
could potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2013-1735, CVE-2013-1736)

Boris Zbarsky discovered that user-defined getters on DOM proxies would
use the expando object as 'this'. An attacker could potentially exploit
this by tricking add-on code in to making incorrect security sensitive
decisions based on malicious values. (CVE-2013-1737)

A use-after-free bug was discovered in Firefox. An attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2013-1738)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
