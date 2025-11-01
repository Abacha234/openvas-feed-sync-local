# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843713");
  script_cve_id("CVE-2018-1000805");
  script_tag(name:"creation_date", value:"2018-10-26 04:10:11 +0000 (Fri, 26 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-06 18:35:00 +0000 (Wed, 06 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-3796-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3796-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3796-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'paramiko' package(s) announced via the USN-3796-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3796-1 fixed a vulnerability in Paramiko. This update provides the
corresponding update for Ubuntu 18.10.

Original advisory details:

 Daniel Hoffman discovered that Paramiko incorrectly handled authentication
 when being used as a server. A remote attacker could use this issue to
 bypass authentication without any credentials.");

  script_tag(name:"affected", value:"'paramiko' package(s) on Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
