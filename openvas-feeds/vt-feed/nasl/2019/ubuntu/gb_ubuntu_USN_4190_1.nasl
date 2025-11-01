# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844239");
  script_cve_id("CVE-2018-14498", "CVE-2018-19664", "CVE-2018-20330", "CVE-2019-2201");
  script_tag(name:"creation_date", value:"2019-11-14 03:01:54 +0000 (Thu, 14 Nov 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4190-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4190-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4190-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjpeg-turbo' package(s) announced via the USN-4190-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libjpeg-turbo incorrectly handled certain BMP images.
An attacker could possibly use this issue to expose sensitive information.
This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2018-14498)

It was discovered that libjpeg-turbo incorrectly handled certain JPEG images.
An attacker could possibly use this issue to expose sensitive information.
This issue only affected Ubuntu 19.04. (CVE-2018-19664)

It was discovered that libjpeg-turbo incorrectly handled certain BMP images.
An attacker could possibly use this issue to execute arbitrary code. This
issue only affected Ubuntu 19.04. (CVE-2018-20330)

It was discovered that libjpeg-turbo incorrectly handled certain JPEG images.
An attacker could possibly cause a denial of service or execute arbitrary code.
(CVE-2019-2201)");

  script_tag(name:"affected", value:"'libjpeg-turbo' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
