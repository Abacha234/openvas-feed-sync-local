# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842535");
  script_cve_id("CVE-2015-1819", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8035");
  script_tag(name:"creation_date", value:"2015-11-17 04:31:05 +0000 (Tue, 17 Nov 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2812-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2812-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2812-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the USN-2812-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer discovered that libxml2 incorrectly handled certain XML
data. If a user or automated system were tricked into opening a specially
crafted document, an attacker could possibly cause resource consumption,
resulting in a denial of service. This issue only affected
Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-1819)

Michal Zalewski discovered that libxml2 incorrectly handled certain XML
data. If a user or automated system were tricked into opening a specially
crafted document, an attacker could possibly cause libxml2 to crash,
resulting in a denial of service. This issue only affected
Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-7941)

Kostya Serebryany discovered that libxml2 incorrectly handled certain XML
data. If a user or automated system were tricked into opening a specially
crafted document, an attacker could possibly cause libxml2 to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-7942)

Gustavo Grieco discovered that libxml2 incorrectly handled certain XML
data. If a user or automated system were tricked into opening a specially
crafted document, an attacker could possibly cause libxml2 to crash,
resulting in a denial of service. This issue only affected
Ubuntu 14.04 LTS. (CVE-2015-8035)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
