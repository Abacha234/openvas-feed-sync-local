# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845334");
  script_cve_id("CVE-2022-24765");
  script_tag(name:"creation_date", value:"2022-04-26 01:00:22 +0000 (Tue, 26 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-23 02:10:00 +0000 (Sat, 23 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5376-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5376-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5376-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the USN-5376-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5376-1 fixed vulnerabilities in Git. This update provides the corresponding
updates for Ubuntu 22.04 LTS.

Original advisory details:

 Yu Chen Dong discovered that Git incorrectly handled certain repository paths
 in platforms with multiple users support. An attacker could possibly use
 this issue to run arbitrary commands.");

  script_tag(name:"affected", value:"'git' package(s) on Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
