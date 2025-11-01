# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856677");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-23206", "CVE-2024-23213", "CVE-2024-23222", "CVE-2024-23271", "CVE-2024-27808", "CVE-2024-27820", "CVE-2024-27833", "CVE-2024-27834", "CVE-2024-27838", "CVE-2024-27851", "CVE-2024-40866", "CVE-2024-44187", "CVE-2024-4558");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 17:18:09 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-11-02 05:01:00 +0000 (Sat, 02 Nov 2024)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2024:3869-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3869-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MVXMAVENCG7GTOWMBTHFWE7ALKVFMG5S");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2024:3869-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  Update to version 2.46.0 (bsc#1231039).

  * CVE-2024-40866

  * CVE-2024-44187

  Already fixed in version 2.44.3:

  * CVE-2024-4558

  * CVE-2024-27838

  * CVE-2024-27851

  Already fixed in version 2.44.2:

  * CVE-2024-27834

  * CVE-2024-27808

  * CVE-2024-27820

  * CVE-2024-27833

  Already fixed in version 2.44.1:

  * CVE-2024-23222

  * CVE-2024-23206

  * CVE-2024-23213

  * CVE-2024-23271");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
