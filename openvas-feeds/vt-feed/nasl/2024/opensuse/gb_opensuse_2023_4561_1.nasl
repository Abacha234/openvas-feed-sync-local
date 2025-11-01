# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833544");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-32919", "CVE-2022-32933", "CVE-2022-46705", "CVE-2022-46725", "CVE-2023-32359", "CVE-2023-41983", "CVE-2023-42852");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-02 18:25:16 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:01:35 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2023:4561-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4561-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/555LBEV3MH4RIOFVLKWAEGWKYWDRIHFE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2023:4561-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  Update to version 2.42.2 (bsc#1217210):

  * CVE-2023-41983: Processing web content may lead to a denial-of-service.

  * CVE-2023-42852: Processing web content may lead to arbitrary code execution.

  Already previously fixed:

  * CVE-2022-32919: Visiting a website that frames malicious content may lead to
      UI spoofing (fixed already in 2.38.4).

  * CVE-2022-32933: A website may be able to track the websites a user visited
      in private browsing mode (fixed already in 2.38.0).

  * CVE-2022-46705: Visiting a malicious website may lead to address bar
      spoofing (fixed already in 2.38.4).

  * CVE-2022-46725: Visiting a malicious website may lead to address bar
      spoofing (fixed already in 2.38.4).

  * CVE-2023-32359: A users password may be read aloud by a text-to-speech
      accessibility feature (fixed already in 2.42.0).

  ##");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
