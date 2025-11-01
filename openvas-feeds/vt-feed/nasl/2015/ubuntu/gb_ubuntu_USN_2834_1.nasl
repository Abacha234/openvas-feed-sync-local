# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842557");
  script_cve_id("CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317");
  script_tag(name:"creation_date", value:"2015-12-15 04:47:02 +0000 (Tue, 15 Dec 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2834-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2834-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2834-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the USN-2834-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kostya Serebryany discovered that libxml2 incorrectly handled certain
malformed documents. If a user or automated system were tricked into
opening a specially crafted document, an attacker could possibly cause
libxml2 to crash, resulting in a denial of service. (CVE-2015-5312,
CVE-2015-7497, CVE-2015-7498, CVE-2015-7499,CVE-2015-7500)

Hugh Davenport discovered that libxml2 incorrectly handled certain
malformed documents. If a user or automated system were tricked into
opening a specially crafted document, an attacker could possibly cause
libxml2 to crash, resulting in a denial of service. (CVE-2015-8241,
CVE-2015-8242)

Hanno Boeck discovered that libxml2 incorrectly handled certain
malformed documents. If a user or automated system were tricked into
opening a specially crafted document, an attacker could possibly cause
libxml2 to crash, resulting in a denial of service. This issue only applied
to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-8317)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
