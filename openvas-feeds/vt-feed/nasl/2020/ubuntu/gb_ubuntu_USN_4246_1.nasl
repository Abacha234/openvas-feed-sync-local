# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844303");
  script_cve_id("CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843");
  script_tag(name:"creation_date", value:"2020-01-23 04:00:20 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 16:40:00 +0000 (Mon, 27 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-4246-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4246-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4246-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zlib' package(s) announced via the USN-4246-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that zlib incorrectly handled pointer arithmetic. An attacker
could use this issue to cause zlib to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2016-9840, CVE-2016-9841)

It was discovered that zlib incorrectly handled vectors involving left shifts of
negative integers. An attacker could use this issue to cause zlib to
crash, resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2016-9842)

It was discovered that zlib incorrectly handled vectors involving big-endian CRC
calculation. An attacker could use this issue to cause zlib to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2016-9843)");

  script_tag(name:"affected", value:"'zlib' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
