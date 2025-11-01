# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845298");
  script_cve_id("CVE-2021-3426", "CVE-2021-4189", "CVE-2022-0391");
  script_tag(name:"creation_date", value:"2022-03-29 01:00:53 +0000 (Tue, 29 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-17 22:17:00 +0000 (Thu, 17 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5342-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5342-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5342-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7, python3.4, python3.5, python3.6, python3.8' package(s) announced via the USN-5342-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Schworer discovered that Python incorrectly handled certain inputs.
An attacker could possibly use this issue to expose sensitive information.
This issue only affected Ubuntu 18.04 LTS. (CVE-2021-3426)

It was discovered that Python incorrectly handled certain FTP requests.
An attacker could possibly use this issue to expose sensitive information.
This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM, and Ubuntu 18.04 LTS.
(CVE-2021-4189)

It was discovered that Python incorrectly handled certain inputs.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2022-0391)");

  script_tag(name:"affected", value:"'python2.7, python3.4, python3.5, python3.6, python3.8' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
