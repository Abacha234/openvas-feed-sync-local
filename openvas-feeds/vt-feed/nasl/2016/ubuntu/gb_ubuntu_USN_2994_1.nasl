# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842783");
  script_cve_id("CVE-2015-8806", "CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-2073", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4447", "CVE-2016-4449", "CVE-2016-4483");
  script_tag(name:"creation_date", value:"2016-06-07 03:25:23 +0000 (Tue, 07 Jun 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-25 17:24:00 +0000 (Mon, 25 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-2994-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2994-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2994-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the USN-2994-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libxml2 incorrectly handled certain malformed
documents. If a user or automated system were tricked into opening a
specially crafted document, an attacker could possibly cause libxml2 to
crash, resulting in a denial of service. (CVE-2015-8806, CVE-2016-2073,
CVE-2016-3627, CVE-2016-3705, CVE-2016-4447)

It was discovered that libxml2 incorrectly handled certain malformed
documents. If a user or automated system were tricked into opening a
specially crafted document, an attacker could cause libxml2 to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2016-1762, CVE-2016-1834)

Mateusz Jurczyk discovered that libxml2 incorrectly handled certain
malformed documents. If a user or automated system were tricked into
opening a specially crafted document, an attacker could cause libxml2 to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-1833, CVE-2016-1838, CVE-2016-1839)

Wei Lei and Liu Yang discovered that libxml2 incorrectly handled certain
malformed documents. If a user or automated system were tricked into
opening a specially crafted document, an attacker could cause libxml2 to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-1835, CVE-2016-1837)

Wei Lei and Liu Yang discovered that libxml2 incorrectly handled certain
malformed documents. If a user or automated system were tricked into
opening a specially crafted document, an attacker could cause libxml2 to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only applied to Ubuntu 14.04 LTS, Ubuntu 15.10 and
Ubuntu 16.04 LTS. (CVE-2016-1836)

Kostya Serebryany discovered that libxml2 incorrectly handled certain
malformed documents. If a user or automated system were tricked into
opening a specially crafted document, an attacker could cause libxml2 to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-1840)

It was discovered that libxml2 would load certain XML external entities. If
a user or automated system were tricked into opening a specially crafted
document, an attacker could possibly obtain access to arbitrary files or
cause resource consumption. (CVE-2016-4449)

Gustavo Grieco discovered that libxml2 incorrectly handled certain
malformed documents. If a user or automated system were tricked into
opening a specially crafted document, an attacker could possibly cause
libxml2 to crash, resulting in a denial of service. (CVE-2016-4483)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
