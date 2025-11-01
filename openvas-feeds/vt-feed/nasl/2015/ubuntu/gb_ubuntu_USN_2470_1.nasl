# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842045");
  script_cve_id("CVE-2014-9390");
  script_tag(name:"creation_date", value:"2015-01-23 11:58:04 +0000 (Fri, 23 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-17 19:54:00 +0000 (Mon, 17 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-2470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2470-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2470-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the USN-2470-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matt Mackall and Augie Fackler discovered that Git incorrectly handled certain
filesystem paths. A remote attacker could possibly use this issue to execute
arbitrary code if the Git tree is stored in an HFS+ or NTFS filesystem. The
remote attacker would need write access to a Git repository that the victim
pulls from.");

  script_tag(name:"affected", value:"'git' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
