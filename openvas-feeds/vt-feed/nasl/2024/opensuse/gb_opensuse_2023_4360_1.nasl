# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833675");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-40474");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-17 15:36:32 +0000 (Tue, 17 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 07:17:09 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for gstreamer (SUSE-SU-2023:4360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4360-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/B6Y7MDQCBM4T6UYH33S2U7QON7Q5ZUSM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer'
  package(s) announced via the SUSE-SU-2023:4360-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-bad fixes the following issues:

  * CVE-2023-40474: Fixed a remote code execution issue due to improper parsing
      of H265 encoded video files (bsc#1215793).

  ##");

  script_tag(name:"affected", value:"'gstreamer' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
