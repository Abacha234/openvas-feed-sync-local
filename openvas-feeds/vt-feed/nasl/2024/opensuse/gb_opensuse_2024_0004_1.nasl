# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833654");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-32359", "CVE-2023-39928", "CVE-2023-40451", "CVE-2023-41074", "CVE-2023-42883", "CVE-2023-42890");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 18:10:56 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:54:45 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2024:0004-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0004-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/75DTNX7FG3DGG3YULTYJ5JAMEI2A4BKV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2024:0004-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  * CVE-2023-42890: Fixed processing malicious web content may lead to arbitrary
      code execution (bsc#1218033).

  * CVE-2023-42883: Fixed processing a malicious image may lead to a denial-of-
      service (bsc#1218032).

  * CVE-2023-41074: Fixed use-after-free in the MediaRecorder API of the WebKit
      GStreamer-based ports (bsc#1215870).

  * CVE-2023-40451, CVE-2023-41074: Update to version 2.42.4 (bsc#1218032,
      bsc#1215868).

  ##");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
