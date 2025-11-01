# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840391");
  script_cve_id("CVE-2009-2625", "CVE-2009-3560", "CVE-2009-3720");
  script_tag(name:"creation_date", value:"2010-02-19 12:38:15 +0000 (Fri, 19 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-890-5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-890-5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-890-5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xmlrpc-c' package(s) announced via the USN-890-5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-890-1 fixed vulnerabilities in Expat. This update provides the
corresponding updates for XML-RPC for C and C++.

Original advisory details:

 Jukka Taimisto, Tero Rontti and Rauli Kaksonen discovered that Expat did
 not properly process malformed XML. If a user or application linked against
 Expat were tricked into opening a crafted XML file, an attacker could cause
 a denial of service via application crash. (CVE-2009-2625, CVE-2009-3720)

 It was discovered that Expat did not properly process malformed UTF-8
 sequences. If a user or application linked against Expat were tricked into
 opening a crafted XML file, an attacker could cause a denial of service via
 application crash. (CVE-2009-3560)");

  script_tag(name:"affected", value:"'xmlrpc-c' package(s) on Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
