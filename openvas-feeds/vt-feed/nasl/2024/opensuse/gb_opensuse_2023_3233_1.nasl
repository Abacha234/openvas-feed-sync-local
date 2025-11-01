# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833769");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-48503", "CVE-2023-32435", "CVE-2023-32439", "CVE-2023-38133", "CVE-2023-38572", "CVE-2023-38592", "CVE-2023-38594", "CVE-2023-38595", "CVE-2023-38597", "CVE-2023-38599", "CVE-2023-38600", "CVE-2023-38611");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-02 22:14:39 +0000 (Wed, 02 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:46:41 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2023:3233-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3233-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/75BZ6NRRKNVV6TYOT5YFXFDXMXX5P5KV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2023:3233-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  Update to version 2.40.5 (bsc#1213905):

  * CVE-2023-38133: Fixed information disclosure.

  * CVE-2023-38572: Fixed Same-Origin-Policy bypass.

  * CVE-2023-38592: Fixed arbitrary code execution.

  * CVE-2023-38594: Fixed arbitrary code execution.

  * CVE-2023-38595: Fixed arbitrary code execution.

  * CVE-2023-38597: Fixed arbitrary code execution.

  * CVE-2023-38599: Fixed sensitive user information tracking.

  * CVE-2023-38600: Fixed arbitrary code execution.

  * CVE-2023-38611: Fixed arbitrary code execution.

  Update to version 2.40.3 (bsc#1212863):

  * CVE-2023-32439: Fixed a bug where processing maliciously crafted web content
      may lead to arbitrary code execution. (bsc#1212863)

  * CVE-2023-32435: Fixed a bug where processing web content may lead to
      arbitrary code execution. (bsc#1212863)

  * CVE-2022-48503: Fixed a bug where processing web content may lead to
      arbitrary code execution. (bsc#1212863)

  ##");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
