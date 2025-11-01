# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856422");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-39325", "CVE-2023-44487", "CVE-2024-24786");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 19:32:37 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-09-06 04:00:47 +0000 (Fri, 06 Sep 2024)");
  script_name("openSUSE: Security Advisory for kubernetes1.26 (SUSE-SU-2024:3094-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3094-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FT2YYX66CN57PQOIHJR34FH2YLON67JX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.26'
  package(s) announced via the SUSE-SU-2024:3094-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubernetes1.26 fixes the following issues:

  Update kubernetes to version 1.26.15: \- CVE-2024-24786: Fixed infinite loop in
  protojson.Unmarshal in golang-protobuf (bsc#1229867) \- CVE-2023-39325: Fixed a
  flaw that can lead to a DoS due to a rapid stream resets causing excessive work.
  This is also known as CVE-2023-44487. (bsc#1229869) \- CVE-2023-44487: Fixed
  HTTP/2 Rapid Reset attack in net/http (bsc#1229869)

  Other fixes:
  \- Fixed packages required by kubernetes1.26-client installation (bsc#1229008)
  \- Update go to version v1.22.5 (bsc#1229858) \- Add upstream patch for
  reproducible builds (bsc#1062303)

  ##");

  script_tag(name:"affected", value:"'kubernetes1.26' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
