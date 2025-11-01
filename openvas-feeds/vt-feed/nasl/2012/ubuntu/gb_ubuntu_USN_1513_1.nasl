# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841092");
  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836", "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
  script_tag(name:"creation_date", value:"2012-07-26 05:40:08 +0000 (Thu, 26 Jul 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1513-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1513-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1513-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libexif' package(s) announced via the USN-1513-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mateusz Jurczyk discovered that libexif incorrectly parsed certain
malformed EXIF tags. If a user or automated system were tricked into
processing a specially crafted image file, an attacker could cause libexif
to crash, leading to a denial of service, or possibly obtain sensitive
information. (CVE-2012-2812, CVE-2012-2813)

Mateusz Jurczyk discovered that libexif incorrectly parsed certain
malformed EXIF tags. If a user or automated system were tricked into
processing a specially crafted image file, an attacker could cause libexif
to crash, leading to a denial of service, or possibly execute arbitrary
code. (CVE-2012-2814)

Yunho Kim discovered that libexif incorrectly parsed certain malformed EXIF
tags. If a user or automated system were tricked into processing a
specially crafted image file, an attacker could cause libexif to crash,
leading to a denial of service, or possibly obtain sensitive information.
(CVE-2012-2836)

Yunho Kim discovered that libexif incorrectly parsed certain malformed EXIF
tags. If a user or automated system were tricked into processing a
specially crafted image file, an attacker could cause libexif to crash,
leading to a denial of service. (CVE-2012-2837)

Dan Fandrich discovered that libexif incorrectly parsed certain malformed
EXIF tags. If a user or automated system were tricked into processing a
specially crafted image file, an attacker could cause libexif to crash,
leading to a denial of service, or possibly execute arbitrary code.
(CVE-2012-2840, CVE-2012-2841)");

  script_tag(name:"affected", value:"'libexif' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
