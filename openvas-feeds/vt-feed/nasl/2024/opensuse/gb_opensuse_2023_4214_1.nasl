# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833587");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-5721", "CVE-2023-5722", "CVE-2023-5723", "CVE-2023-5724", "CVE-2023-5725", "CVE-2023-5726", "CVE-2023-5727", "CVE-2023-5728", "CVE-2023-5729", "CVE-2023-5730", "CVE-2023-5731");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-01 19:27:41 +0000 (Wed, 01 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:36:29 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for MozillaFirefox (SUSE-SU-2023:4214-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4214-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MB7Q4F3JPDDWYRXFVD2VSJN6I5ZVAX54");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the SUSE-SU-2023:4214-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

  * Updated to version 115.4.0 ESR (bsc#1216338):

  * CVE-2023-5721: Fixed a potential clickjack via queued up rendering.

  * CVE-2023-5722: Fixed a cross-Origin size and header leakage.

  * CVE-2023-5723: Fixed unexpected errors when handling invalid cookie
      characters.

  * CVE-2023-5724: Fixed a crash due to a large WebGL draw.

  * CVE-2023-5725: Fixed an issue where WebExtensions could open arbitrary URLs.

  * CVE-2023-5726: Fixed an issue where fullscreen notifications would be
      obscured by file the open dialog on macOS.

  * CVE-2023-5727: Fixed a download protection bypass on on Windows.

  * CVE-2023-5728: Fixed a crash caused by improper object tracking during GC in
      the JavaScript engine.

  * CVE-2023-5729: Fixed an issue where fullscreen notifications would be
      obscured by WebAuthn prompts.

  * CVE-2023-5730: Fixed multiple memory safety issues.

  * CVE-2023-5731: Fixed multiple memory safety issues.

  ##");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
