# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856229");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-5688", "CVE-2024-5690", "CVE-2024-5691", "CVE-2024-5692", "CVE-2024-5693", "CVE-2024-5696", "CVE-2024-5700", "CVE-2024-5702");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-16 14:44:05 +0000 (Fri, 16 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-06-19 04:00:27 +0000 (Wed, 19 Jun 2024)");
  script_name("openSUSE: Security Advisory for MozillaFirefox (SUSE-SU-2024:2061-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2061-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YCUMLO2IIP7MC3GZY2YWW6ZG2EPDBEFE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the SUSE-SU-2024:2061-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

  * Update to version 115.12.0 ESR (bsc#1226027)

  * CVE-2024-5702: Use-after-free in networking

  * CVE-2024-5688: Use-after-free in JavaScript object transplant

  * CVE-2024-5690: External protocol handlers leaked by timing attack

  * CVE-2024-5691: Sandboxed iframes were able to bypass sandbox restrictions to
      open a new window

  * CVE-2024-5692: Bypass of file name restrictions during saving

  * CVE-2024-5693: Cross-Origin Image leak via Offscreen Canvas

  * CVE-2024-5696: Memory Corruption in Text Fragments

  * CVE-2024-5700: Memory safety bugs fixed in Firefox 127, Firefox ESR 115.12,
      and Thunderbird 115.12

  ##");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
