# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886830");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-4331", "CVE-2024-4368", "CVE-2024-4058", "CVE-2024-4059", "CVE-2024-4060", "CVE-2024-3833", "CVE-2024-3834", "CVE-2024-3837", "CVE-2024-3839", "CVE-2024-3840", "CVE-2024-3841", "CVE-2024-3843", "CVE-2024-3844", "CVE-2024-3845", "CVE-2024-3846", "CVE-2024-3847", "CVE-2024-3914");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-19 17:20:22 +0000 (Fri, 19 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-05-27 10:48:46 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2024-5cf9499b62)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-5cf9499b62");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UOC3HLIZCGMIJLJ6LME5UWUUIFLXEGRN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2024-5cf9499b62 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
