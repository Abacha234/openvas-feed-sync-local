# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841519");
  script_cve_id("CVE-2013-1701", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717");
  script_tag(name:"creation_date", value:"2013-08-08 06:16:46 +0000 (Thu, 08 Aug 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1925-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1925-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1925-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1208041");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1925-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeff Gilbert and Henrik Skupin discovered multiple memory safety issues
in Thunderbird. If the user were tricked in to opening a specially crafted
message with scripting enabled, an attacker could possibly exploit these
to cause a denial of service via application crash, or potentially execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2013-1701)

It was discovered that a document's URI could be set to the URI of
a different document. If a user had scripting enabled, an attacker
could potentially exploit this to conduct cross-site scripting (XSS)
attacks. (CVE-2013-1709)

A flaw was discovered when generating a CRMF request in certain
circumstances. If a user had scripting enabled, an attacker could
potentially exploit this to conduct cross-site scripting (XSS) attacks,
or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-1710)

Cody Crews discovered that some Javascript components performed security
checks against the wrong URI, potentially bypassing same-origin policy
restrictions. If a user had scripting enabled, an attacker could exploit
this to conduct cross-site scripting (XSS) attacks or install addons
from a malicious site. (CVE-2013-1713)

Federico Lanusse discovered that web workers could bypass cross-origin
checks when using XMLHttpRequest. If a user had scripting enabled, an
attacker could potentially exploit this to conduct cross-site scripting
(XSS) attacks. (CVE-2013-1714)

Georgi Guninski and John Schoenick discovered that Java applets could
access local files under certain circumstances. If a user had scripting
enabled, an attacker could potentially exploit this to steal confidential
data. (CVE-2013-1717)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
