# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845036");
  script_cve_id("CVE-2019-2386");
  script_tag(name:"creation_date", value:"2021-08-26 03:00:22 +0000 (Thu, 26 Aug 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-16 14:35:00 +0000 (Fri, 16 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-5052-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5052-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5052-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mongodb' package(s) announced via the USN-5052-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MongoDB would fail to properly invalidate existing sessions for deleted
users. This could allow a remote authenticated attacker to gain elevated
privileges if their user account was recreated with elevated privileges.");

  script_tag(name:"affected", value:"'mongodb' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
