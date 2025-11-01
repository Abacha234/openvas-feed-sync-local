# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856149");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2020-35654", "CVE-2021-23437", "CVE-2021-25289", "CVE-2021-25290", "CVE-2021-25292", "CVE-2021-25293", "CVE-2021-27921", "CVE-2021-27922", "CVE-2021-27923", "CVE-2021-34552", "CVE-2022-22815", "CVE-2022-22816");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 12:28:43 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"creation_date", value:"2024-05-24 01:00:24 +0000 (Fri, 24 May 2024)");
  script_name("openSUSE: Security Advisory for python (SUSE-SU-2024:1673-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1673-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5TZXHRHFJ6RK7UNSENI24V6MKTK4OENK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the SUSE-SU-2024:1673-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-Pillow fixes the following issues:

  * Fixed ImagePath.Path array handling (bsc#1194552, CVE-2022-22815,
      bsc#1194551, CVE-2022-22816)

  * Use snprintf instead of sprintf (bsc#1188574, CVE-2021-34552)

  * Fix Memory DOS in Icns, Ico and Blp Image Plugins. (bsc#1183110,
      CVE-2021-27921, bsc#1183108, CVE-2021-27922, bsc#1183107, CVE-2021-27923)

  * Fix OOB read in SgiRleDecode.c (bsc#1183102, CVE-2021-25293)

  * Use more specific regex chars to prevent ReDoS (bsc#1183101, CVE-2021-25292)

  * Fix negative size read in TiffDecode.c (bsc#1183105, CVE-2021-25290)

  * Raise ValueError if color specifier is too long (bsc#1190229,
      CVE-2021-23437)

  * Incorrect error code checking in TiffDecode.c (bsc#1183103, CVE-2021-25289)

  * OOB Write in TiffDecode.c (bsc#1180833, CVE-2020-35654)

  ##");

  script_tag(name:"affected", value:"'python' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
