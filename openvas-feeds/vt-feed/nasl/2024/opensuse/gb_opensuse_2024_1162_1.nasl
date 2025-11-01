# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856050");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-52425", "CVE-2023-6597", "CVE-2024-0450");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 02:03:16 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-04-09 01:06:30 +0000 (Tue, 09 Apr 2024)");
  script_name("openSUSE: Security Advisory for python310 (SUSE-SU-2024:1162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1162-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7G2ALVKTKEOALRI4UF5URBF6ON7EXI7J");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python310'
  package(s) announced via the SUSE-SU-2024:1162-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python310 fixes the following issues:

  * CVE-2024-0450: Fixed 'quoted-overlap' in zipfile module is python310
      (bsc#1221854)

  * CVE-2023-52425: Fixed denial of service caused by processing large tokens in
      expat module in python310 (bsc#1219559)

  * CVE-2023-6597: Fixed tempfile.TemporaryDirectory fails on removing dir in
      some edge cases related to symlinks in python310 (bsc#1219666)

  Other changes:

  * Revert %autopatch due to missing parameter support (bsc#1189495)

  * Extended crypto-policies support (bsc#1211301)

  ##");

  script_tag(name:"affected", value:"'python310' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
