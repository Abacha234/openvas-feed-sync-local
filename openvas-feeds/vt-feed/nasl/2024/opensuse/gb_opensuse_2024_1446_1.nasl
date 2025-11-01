# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856106");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-2756", "CVE-2024-3096", "CVE-2022-31629");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:32:25 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"creation_date", value:"2024-04-27 01:00:26 +0000 (Sat, 27 Apr 2024)");
  script_name("openSUSE: Security Advisory for php8 (SUSE-SU-2024:1446-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1446-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/B6D6UI3AE3T6YUE6R3EXQ2NFFKLTJVRH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php8'
  package(s) announced via the SUSE-SU-2024:1446-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php8 fixes the following issues:

  * CVE-2024-2756: Fixed bypass of security fix applied for CVE-2022-31629 that
      lead PHP to consider not secure cookies as secure (bsc#1222857)

  * CVE-2024-3096: Fixed bypass on null byte leading passwords checked via
      password_verify (bsc#1222858)

  ##");

  script_tag(name:"affected", value:"'php8' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
