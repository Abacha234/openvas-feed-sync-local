# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842253");
  script_cve_id("CVE-2010-4651", "CVE-2014-9637", "CVE-2015-1196", "CVE-2015-1395", "CVE-2015-1396");
  script_tag(name:"creation_date", value:"2015-06-24 04:17:46 +0000 (Wed, 24 Jun 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-17 18:15:00 +0000 (Mon, 17 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-2651-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2651-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2651-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'patch' package(s) announced via the USN-2651-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Wilk discovered that GNU patch did not correctly handle file paths in
patch files. An attacker could specially craft a patch file that could
overwrite arbitrary files with the privileges of the user invoking the program.
This issue only affected Ubuntu 12.04 LTS. (CVE-2010-4651)

Laszlo Boszormenyi discovered that GNU patch did not correctly handle some
patch files. An attacker could specially craft a patch file that could cause a
denial of service. (CVE-2014-9637)

Jakub Wilk discovered that GNU patch did not correctly handle symbolic links in
git style patch files. An attacker could specially craft a patch file that
could overwrite arbitrary files with the privileges of the user invoking the
program. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-1196)

Jakub Wilk discovered that GNU patch did not correctly handle file renames in
git style patch files. An attacker could specially craft a patch file that
could overwrite arbitrary files with the privileges of the user invoking the
program. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-1395)

Jakub Wilk discovered the fix for CVE-2015-1196 was incomplete for GNU patch.
An attacker could specially craft a patch file that could overwrite arbitrary
files with the privileges of the user invoking the program. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2015-1396)");

  script_tag(name:"affected", value:"'patch' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
