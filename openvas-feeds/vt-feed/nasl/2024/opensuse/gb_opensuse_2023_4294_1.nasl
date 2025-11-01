# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833793");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-35074", "CVE-2023-39434", "CVE-2023-39928", "CVE-2023-40451", "CVE-2023-41074", "CVE-2023-41993");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-14 15:28:26 +0000 (Wed, 14 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 07:15:33 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2023:4294-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4294-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZOKLILNT22JJX6AXCWWZGM56OIJB6T4X");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2023:4294-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 ships missing Lang packages to SUSE Linux Enterprise
  15 SP4 and SP5.

  Security fixes:

  * CVE-2023-41993: Fixed an issue where processing malicious web content could
      have lead to arbitrary code execution (bsc#1215661).

  * CVE-2023-39928: Fixed a use-after-free that could be exploited to execute
      arbitrary code when visiting a malicious webpage (bsc#1215868).

  * CVE-2023-41074: Fixed an issue where processing malicious web content could
      have lead to arbitrary code execution (bsc#1215870).

  Other fixes:

  * Fixed missing package dependencies (bsc#1215072).

  ##");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
