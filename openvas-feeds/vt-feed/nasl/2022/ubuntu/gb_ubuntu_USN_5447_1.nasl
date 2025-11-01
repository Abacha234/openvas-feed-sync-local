# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845386");
  script_cve_id("CVE-2022-1348");
  script_tag(name:"creation_date", value:"2022-05-27 01:00:30 +0000 (Fri, 27 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 19:04:00 +0000 (Tue, 07 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-5447-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5447-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5447-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'logrotate' package(s) announced via the USN-5447-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that logrotate incorrectly handled the state file. A
local attacker could possibly use this issue to keep a lock on the state
file and cause logrotate to stop working, leading to a denial of service.");

  script_tag(name:"affected", value:"'logrotate' package(s) on Ubuntu 21.10, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
