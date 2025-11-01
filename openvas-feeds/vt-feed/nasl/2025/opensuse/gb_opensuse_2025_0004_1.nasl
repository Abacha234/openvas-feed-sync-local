# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856894");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2019-18848", "CVE-2023-51774");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-14 18:28:22 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"creation_date", value:"2025-01-08 05:00:03 +0000 (Wed, 08 Jan 2025)");
  script_name("openSUSE: Security Advisory for rubygem (openSUSE-SU-2025:0004-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0004-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FICWL2K7EGMUBVQ6CHEQYANYFEU4XBG4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem'
  package(s) announced via the openSUSE-SU-2025:0004-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-json-jwt fixes the following issues:

  - New upstream release 1.16.6, see bundled CHANGELOG.md

  - Remove padding oracle by @btoews

  - Fixes CVE-2023-51774 boo#1220727

  - updated to version 1.11.0

  - no changelog found

  - Fixes CVE-2019-18848 boo#1156649");

  script_tag(name:"affected", value:"'rubygem' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
