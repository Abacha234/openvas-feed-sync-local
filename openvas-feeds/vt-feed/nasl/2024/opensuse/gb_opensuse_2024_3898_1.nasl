# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856687");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-10458", "CVE-2024-10459", "CVE-2024-10460", "CVE-2024-10461", "CVE-2024-10462", "CVE-2024-10463", "CVE-2024-10464", "CVE-2024-10465", "CVE-2024-10466", "CVE-2024-10467");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-04 13:26:32 +0000 (Mon, 04 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-05 05:00:35 +0000 (Tue, 05 Nov 2024)");
  script_name("openSUSE: Security Advisory for MozillaFirefox (SUSE-SU-2024:3898-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3898-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IPK5FOCTB42333ZD74LQ3SZOYHZEW7ZV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the SUSE-SU-2024:3898-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

  Firefox Extended Support Release 128.4.0 ESR (bsc#1231879):

  * CVE-2024-10458: Permission leak via embed or object elements

  * CVE-2024-10459: Use-after-free in layout with accessibility

  * CVE-2024-10460: Confusing display of origin for external protocol handler
      prompt

  * CVE-2024-10461: XSS due to Content-Disposition being ignored in
      multipart/x-mixed-replace response

  * CVE-2024-10462: Origin of permission prompt could be spoofed by long URL

  * CVE-2024-10463: Cross origin video frame leak

  * CVE-2024-10464: History interface could have been used to cause a Denial of
      Service condition in the browser

  * CVE-2024-10465: Clipboard 'paste' button persisted across tabs

  * CVE-2024-10466: DOM push subscription message could hang Firefox

  * CVE-2024-10467: Memory safety bugs fixed in Firefox 132, Thunderbird 132,
      Firefox ESR 128.4, and Thunderbird 128.4");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
