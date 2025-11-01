# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856319");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-21131", "CVE-2024-21138", "CVE-2024-21140", "CVE-2024-21145", "CVE-2024-21147");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 23:15:16 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-24 04:00:33 +0000 (Wed, 24 Jul 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:2578-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2578-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OCROIEPC6THE2WUVEFSV2FU662FP5SEV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:2578-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-21-openjdk fixes the following issues:

  Updated to version 21.0.4+7 (July 2024 CPU):

  * CVE-2024-21131: Fixed a potential UTF8 size overflow (bsc#1228046).

  * CVE-2024-21138: Fixed an infinite loop due to excessive symbol length
      (bsc#1228047).

  * CVE-2024-21140: Fixed a pre-loop limit overflow in Range Check Elimination
      (bsc#1228048).

  * CVE-2024-21147: Fixed an out-of-bounds access in 2D image handling
      (bsc#1228052).

  * CVE-2024-21145: Fixed an index overflow in RangeCheckElimination
      (bsc#1228051).");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
