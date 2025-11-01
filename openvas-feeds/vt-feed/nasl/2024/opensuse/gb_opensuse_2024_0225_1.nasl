# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856333");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-40724");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 20:15:57 +0000 (Wed, 07 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-07-28 04:00:20 +0000 (Sun, 28 Jul 2024)");
  script_name("openSUSE: Security Advisory for assimp (openSUSE-SU-2024:0225-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0225-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GRHXRZKHWQMKKB7V55J2TDPZAKJSN2BF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'assimp'
  package(s) announced via the openSUSE-SU-2024:0225-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for assimp fixes the following issues:

  - CVE-2024-40724: Fixed heap-based buffer overflow in the PLY importer
       class (boo#1228142).");

  script_tag(name:"affected", value:"'assimp' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
