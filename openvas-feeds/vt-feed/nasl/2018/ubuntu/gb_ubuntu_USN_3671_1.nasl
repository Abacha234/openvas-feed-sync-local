# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843545");
  script_cve_id("CVE-2018-11233", "CVE-2018-11235");
  script_tag(name:"creation_date", value:"2018-06-07 03:47:44 +0000 (Thu, 07 Jun 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-02 00:15:00 +0000 (Sat, 02 May 2020)");

  script_name("Ubuntu: Security Advisory (USN-3671-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3671-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3671-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the USN-3671-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Etienne Stalmans discovered that git did not properly validate git
submodules files. A remote attacker could possibly use this to craft a
git repo that causes arbitrary code execution when 'git clone
--recurse-submodules' is used. (CVE-2018-11235)

It was discovered that an integer overflow existed in git's pathname
 consistency checking code when used on NTFS filesystems. An attacker could
use this to cause a denial of service or expose sensitive information.
(CVE-2018-11233)");

  script_tag(name:"affected", value:"'git' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
