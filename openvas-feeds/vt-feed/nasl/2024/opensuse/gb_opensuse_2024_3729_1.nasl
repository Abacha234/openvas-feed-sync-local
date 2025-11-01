# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856612");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-8925", "CVE-2024-8927", "CVE-2024-9026");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-16 18:28:34 +0000 (Wed, 16 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-19 04:00:40 +0000 (Sat, 19 Oct 2024)");
  script_name("openSUSE: Security Advisory for php8 (SUSE-SU-2024:3729-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3729-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/J2XACYTTN3573N5WMITQPDYB6BRAIL3H");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php8'
  package(s) announced via the SUSE-SU-2024:3729-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php8 fixes the following issues:

  Update to php 8.2.24:

  * CVE-2024-8925: Fixed erroneous parsing of multipart form data in HTTP POST
      requests leads to legitimate data not being processed (bsc#1231360)

  * CVE-2024-8927: Fixed cgi.force_redirect configuration is bypassable due to
      an environment variable collision (bsc#1231358)

  * CVE-2024-9026: Fixed pollution of worker output logs in PHP-FPM
      (bsc#1231382)");

  script_tag(name:"affected", value:"'php8' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
