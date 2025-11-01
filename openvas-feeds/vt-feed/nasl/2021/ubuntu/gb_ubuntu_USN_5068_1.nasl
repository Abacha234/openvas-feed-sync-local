# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845049");
  script_cve_id("CVE-2017-6363", "CVE-2021-38115", "CVE-2021-40145");
  script_tag(name:"creation_date", value:"2021-09-09 01:00:43 +0000 (Thu, 09 Sep 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-27 19:09:00 +0000 (Thu, 27 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-5068-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5068-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5068-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgd2' package(s) announced via the USN-5068-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GD Graphics Library incorrectly handled certain GD and GD2 files.
An attacker could possibly use this issue to cause a crash or expose sensitive information.
This issue only affected Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 ESM, and Ubuntu 14.04 ESM.
(CVE-2017-6363)

It was discovered that GD Graphics Library incorrectly handled certain TGA files.
An attacker could possibly use this issue to cause a denial of service or
expose sensitive information. (CVE-2021-381)

It was discovered that GD Graphics Library incorrectly handled certain files.
An attacker could possibly use this issue to cause a crash.
(CVE-2021-40145)");

  script_tag(name:"affected", value:"'libgd2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
