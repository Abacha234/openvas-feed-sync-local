# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64649");
  script_cve_id("CVE-2008-3529", "CVE-2009-2414", "CVE-2009-2416");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-815-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-815-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-815-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the USN-815-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libxml2 did not correctly handle root XML document
element DTD definitions. If a user were tricked into processing a specially
crafted XML document, a remote attacker could cause the application linked
against libxml2 to crash, leading to a denial of service. (CVE-2009-2414)

It was discovered that libxml2 did not correctly parse Notation and
Enumeration attribute types. If a user were tricked into processing a
specially crafted XML document, a remote attacker could cause the
application linked against libxml2 to crash, leading to a denial of
service. (CVE-2009-2416)

USN-644-1 fixed a vulnerability in libxml2. This advisory provides the
corresponding update for Ubuntu 9.04.

Original advisory details:

 It was discovered that libxml2 did not correctly handle long entity names.
 If a user were tricked into processing a specially crafted XML document, a
 remote attacker could execute arbitrary code with user privileges or cause
 the application linked against libxml2 to crash, leading to a denial of
 service. (CVE-2008-3529)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
