# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843208");
  script_cve_id("CVE-2017-5974", "CVE-2017-5975", "CVE-2017-5976", "CVE-2017-5978", "CVE-2017-5979", "CVE-2017-5980", "CVE-2017-5981");
  script_tag(name:"creation_date", value:"2017-06-16 05:00:17 +0000 (Fri, 16 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3320-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3320-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zziplib' package(s) announced via the USN-3320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Agostino Sarubbo discovered that zziplib incorrectly handled certain
malformed ZIP files. If a user or automated system were tricked into
opening a specially crafted ZIP file, a remote attacker could cause zziplib
to crash, resulting in a denial of service, or possibly execute arbitrary
code.");

  script_tag(name:"affected", value:"'zziplib' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
