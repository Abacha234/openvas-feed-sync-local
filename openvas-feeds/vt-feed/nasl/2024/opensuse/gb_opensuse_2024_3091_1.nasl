# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856439");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-40776", "CVE-2024-40779", "CVE-2024-40780", "CVE-2024-40782", "CVE-2024-40785", "CVE-2024-40789", "CVE-2024-40794", "CVE-2024-4558");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 17:18:09 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-09-06 04:01:39 +0000 (Fri, 06 Sep 2024)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2024:3091-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3091-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OE4ILYHZCUFXSJON7Z3CGOKWVTI6ELJW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2024:3091-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  Update to version 2.44.3 (bsc#1228696 bsc#1228697 bsc#1228698):

  * Fix web process cache suspend/resume when sandbox is enabled.

  * Fix accelerated images disappearing after scrolling.

  * Fix video flickering with DMA-BUF sink.

  * Fix pointer lock on X11.

  * Fix movement delta on mouse events in GTK3.

  * Undeprecate console message API and make it available in 2022 API.

  * Fix several crashes and rendering issues.

  * Security fixes: CVE-2024-40776, CVE-2024-40779, CVE-2024-40780,
      CVE-2024-40782, CVE-2024-40785, CVE-2024-40789, CVE-2024-40794,
      CVE-2024-4558.

  ##");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
