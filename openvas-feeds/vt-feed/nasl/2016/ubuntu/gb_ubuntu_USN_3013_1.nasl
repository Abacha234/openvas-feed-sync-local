# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842800");
  script_cve_id("CVE-2012-6702", "CVE-2015-1283", "CVE-2016-0718", "CVE-2016-4472", "CVE-2016-5300");
  script_tag(name:"creation_date", value:"2016-06-21 03:47:53 +0000 (Tue, 21 Jun 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:05:00 +0000 (Mon, 27 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-3013-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3013-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3013-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xmlrpc-c' package(s) announced via the USN-3013-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Expat code in XML-RPC for C and C++ unexpectedly
called srand in certain circumstances. This could reduce the security of
calling applications. (CVE-2012-6702)

It was discovered that the Expat code in XML-RPC for C and C++ incorrectly
handled seeding the random number generator. A remote attacker could
possibly use this issue to cause a denial of service. (CVE-2016-5300)

Gustavo Grieco discovered that the Expat code in XML-RPC for C and C++
incorrectly handled malformed XML data. If a user or application linked
against XML-RPC for C and C++ were tricked into opening a crafted XML file,
an attacker could cause a denial of service, or possibly execute arbitrary
code. (CVE-2016-0718)

It was discovered that the Expat code in XML-RPC for C and C++ incorrectly
handled malformed XML data. If a user or application linked against XML-RPC
for C and C++ were tricked into opening a crafted XML file, an attacker
could cause a denial of service, or possibly execute arbitrary code.
(CVE-2015-1283, CVE-2016-4472)");

  script_tag(name:"affected", value:"'xmlrpc-c' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
