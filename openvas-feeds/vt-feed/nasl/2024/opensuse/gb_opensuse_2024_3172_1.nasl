# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856454");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-38473", "CVE-2024-38474", "CVE-2024-39884");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-21 15:03:30 +0000 (Wed, 21 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-09-11 04:00:24 +0000 (Wed, 11 Sep 2024)");
  script_name("openSUSE: Security Advisory for apache2 (SUSE-SU-2024:3172-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3172-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BJOECPGHRQQYHQYKYWRBQGB5R3J5E2NG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the SUSE-SU-2024:3172-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2 fixes the following issues:

  * CVE-2024-38474: Fixed substitution encoding issue in mod_rewrite
      (bsc#1227278)

  * CVE-2024-38473: Fixed encoding problem in mod_proxy (bsc#1227276)

  * CVE-2024-39884: Fixed source code disclosure with handlers configured via
      AddType (bsc#1227353)

  ##");

  script_tag(name:"affected", value:"'apache2' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
