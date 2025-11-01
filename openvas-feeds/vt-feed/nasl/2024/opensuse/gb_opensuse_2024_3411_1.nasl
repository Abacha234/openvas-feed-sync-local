# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856514");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-6232", "CVE-2024-7592", "CVE-2024-8088");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-20 16:02:16 +0000 (Tue, 20 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-09-26 04:01:53 +0000 (Thu, 26 Sep 2024)");
  script_name("openSUSE: Security Advisory for python39 (SUSE-SU-2024:3411-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3411-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QNXFOIXBCGZTXD6BKYGBL3VDWS6RK6AB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python39'
  package(s) announced via the SUSE-SU-2024:3411-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python39 fixes the following issues:

  * Update to 3.9.20:

  * CVE-2024-6232: excessive backtracking when parsing tarfile headers leads to
      ReDoS. (bsc#1230227)

  * CVE-2024-7592: quadratic algorithm used when parsing cookies leads to
      excessive resource consumption. (bsc#1229596)

  * CVE-2024-8088: lack of name validation when extracting a zip archive leads
      to infinite loops. (bsc#1229704)");

  script_tag(name:"affected", value:"'python39' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
