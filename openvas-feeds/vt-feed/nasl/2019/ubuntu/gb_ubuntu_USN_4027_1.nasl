# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844062");
  script_cve_id("CVE-2019-10164");
  script_tag(name:"creation_date", value:"2019-06-21 02:00:53 +0000 (Fri, 21 Jun 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-02 14:34:00 +0000 (Fri, 02 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-4027-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4027-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4027-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-10, postgresql-11' package(s) announced via the USN-4027-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander Lakhin discovered that PostgreSQL incorrectly handled
authentication. An authenticated attacker or a rogue server could use this
issue to cause PostgreSQL to crash, resulting in a denial of service, or
possibly execute arbitrary code. The default compiler options for affected
releases should reduce the vulnerability to a denial of service.");

  script_tag(name:"affected", value:"'postgresql-10, postgresql-11' package(s) on Ubuntu 18.04, Ubuntu 18.10, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
