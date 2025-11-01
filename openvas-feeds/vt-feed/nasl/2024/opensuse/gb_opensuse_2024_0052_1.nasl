# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833478");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2018-17144");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-13 17:05:04 +0000 (Wed, 13 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:53:59 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for bitcoin (openSUSE-SU-2024:0052-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0052-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QVS4SN3G7GHI3M44QGZ5RO5NWOGIM4SH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bitcoin'
  package(s) announced via the openSUSE-SU-2024:0052-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bitcoin fixes the following issues:

     Update to version 26.0, including the following changes:

  - Enable LTO and test package for Leap

  - Enable sqlite3 support for wallet

  - Enable asm optimizations unconditionally");

  script_tag(name:"affected", value:"'bitcoin' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
