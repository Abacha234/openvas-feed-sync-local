# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833702");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-28198", "CVE-2023-32370", "CVE-2023-37450", "CVE-2023-38594", "CVE-2023-38595", "CVE-2023-38597", "CVE-2023-38599", "CVE-2023-38600", "CVE-2023-38611", "CVE-2023-40397");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-12 12:02:28 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:18:24 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2023:3753-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3753-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JG5YNAHVCTC343KDMLOHP6GZOXSI7HKR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2023:3753-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  * Expand lang sub-package in spec file unconditionally to handle previous name
      change from WebKit2GTK-lang to WebKitGTK-lang. This change affected the
      automatic generated Requires tag on WebKit2GTK-%{_apiver}, then getting out
      of sync of what's being required and what's being provided. Now, any sub-
      package that was providing WebKit2GTK-%{_apiver} will provide
      WebKitGTK-%{_apiver} instead (bsc#1214835, bsc#1214640, bsc#1214093).

  * Require libwaylandclient0  = 1.20. 15.4 originally had 1.19.0, but webkitgtk
      uses a function added in 1.20.0, so we need to ensure that the wayland
      update is pulled in (bsc#1215072).

  * Update to version 2.40.5 (bsc#1213905 bsc#1213379 bsc#1213581 bsc#1215230):
      CVE-2023-38594, CVE-2023-38595, CVE-2023-38597, CVE-2023-38599,
      CVE-2023-38600, CVE-2023-38611, CVE-2023-40397, CVE-2023-37450,
      CVE-2023-28198, CVE-2023-32370

  ##");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
