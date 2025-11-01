# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842538");
  script_cve_id("CVE-2012-3425", "CVE-2015-7981", "CVE-2015-8126");
  script_tag(name:"creation_date", value:"2015-11-20 05:27:51 +0000 (Fri, 20 Nov 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2815-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2815-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2815-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng' package(s) announced via the USN-2815-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mikulas Patocka discovered that libpng incorrectly handled certain large
fields. If a user or automated system using libpng were tricked into
opening a specially crafted image, an attacker could exploit this to cause
libpng to crash, leading to a denial of service. This issue only affected
Ubuntu 12.04 LTS. (CVE-2012-3425)

Qixue Xiao discovered that libpng incorrectly handled certain time values.
If a user or automated system using libpng were tricked into opening a
specially crafted image, an attacker could exploit this to cause libpng to
crash, leading to a denial of service. (CVE-2015-7981)

It was discovered that libpng incorrectly handled certain small bit-depth
values. If a user or automated system using libpng were tricked into
opening a specially crafted image, an attacker could exploit this to cause
a denial of service or execute code with the privileges of the user
invoking the program. (CVE-2015-8126)");

  script_tag(name:"affected", value:"'libpng' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
