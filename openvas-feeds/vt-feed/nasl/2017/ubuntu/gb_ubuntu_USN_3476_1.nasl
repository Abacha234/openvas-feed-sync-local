# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843362");
  script_cve_id("CVE-2016-1255", "CVE-2017-8806");
  script_tag(name:"creation_date", value:"2017-11-10 06:21:24 +0000 (Fri, 10 Nov 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-21 20:37:00 +0000 (Thu, 21 Dec 2017)");

  script_name("Ubuntu: Security Advisory (USN-3476-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3476-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3476-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-common' package(s) announced via the USN-3476-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dawid Golunski discovered that the postgresql-common pg_ctlcluster script
incorrectly handled symlinks. A local attacker could possibly use this
issue to escalate privileges. This issue only affected Ubuntu 14.04 LTS and
Ubuntu 16.04 LTS. (CVE-2016-1255)

It was discovered that the postgresql-common helper scripts incorrectly
handled symlinks. A local attacker could possibly use this issue to
escalate privileges. (CVE-2017-8806)");

  script_tag(name:"affected", value:"'postgresql-common' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
