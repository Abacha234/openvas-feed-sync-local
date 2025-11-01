# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856420");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2020-22027", "CVE-2021-38291", "CVE-2023-51798");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 19:54:22 +0000 (Wed, 02 Jun 2021)");
  script_tag(name:"creation_date", value:"2024-09-06 04:00:35 +0000 (Fri, 06 Sep 2024)");
  script_name("openSUSE: Security Advisory for ffmpeg (SUSE-SU-2024:3114-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3114-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2K5WWIOUI3MTA3N56IQDQQGJPROXYP66");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the SUSE-SU-2024:3114-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg fixes the following issues:

  * CVE-2020-22027: Fixed heap-based Buffer Overflow vulnerability exits in
      deflate16 at libavfilter/vf_neighbor.c (bsc#1186607)

  * CVE-2021-38291: Fixed an assertion failure at src/libavutil/mathematics.c
      (bsc#1189428)

  * CVE-2023-51798: Fixed floating point exception(FPE) via the interpolate
      function (bsc#1223304)

  ##");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
