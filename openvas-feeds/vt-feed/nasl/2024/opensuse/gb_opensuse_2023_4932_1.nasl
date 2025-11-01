# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833799");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-6185", "CVE-2023-6186");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-14 14:41:30 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:16:18 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for libreoffice (SUSE-SU-2023:4932-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4932-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZJD7AWTPPX45GNG2AUUABCEU757DBVZZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice'
  package(s) announced via the SUSE-SU-2023:4932-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libreoffice fixes the following issues:

  * CVE-2023-6186: Fixed link targets allow arbitrary script execution
      (bsc#1217578).

  * CVE-2023-6185: Fixed Improper input validation enabling arbitrary Gstreamer
      pipeline injection (bsc#1217577).

  ##");

  script_tag(name:"affected", value:"'libreoffice' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
