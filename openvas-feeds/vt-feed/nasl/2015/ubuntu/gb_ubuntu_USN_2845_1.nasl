# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842570");
  script_cve_id("CVE-2014-3925", "CVE-2015-7529");
  script_tag(name:"creation_date", value:"2015-12-18 04:44:37 +0000 (Fri, 18 Dec 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 15:52:00 +0000 (Fri, 27 Sep 2019)");

  script_name("Ubuntu: Security Advisory (USN-2845-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2845-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2845-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sosreport' package(s) announced via the USN-2845-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dolev Farhi discovered an information disclosure issue in SoS. If the
/etc/fstab file contained passwords, the passwords were included in the
SoS report. This issue only affected Ubuntu 14.04 LTS. (CVE-2014-3925)

Mateusz Guzik discovered that SoS incorrectly handled temporary files. A
local attacker could possibly use this issue to overwrite arbitrary files
or gain access to temporary file contents containing sensitive system
information. (CVE-2015-7529)");

  script_tag(name:"affected", value:"'sosreport' package(s) on Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
