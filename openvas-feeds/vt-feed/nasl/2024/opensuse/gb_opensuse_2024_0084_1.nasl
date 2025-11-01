# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856034");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-1669", "CVE-2024-1670", "CVE-2024-1671", "CVE-2024-1672", "CVE-2024-1673", "CVE-2024-1674", "CVE-2024-1675", "CVE-2024-1676", "CVE-2024-2173", "CVE-2024-2174", "CVE-2024-2176", "CVE-2024-2400");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-19 20:21:05 +0000 (Thu, 19 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 09:31:14 +0000 (Mon, 25 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2024:0084-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0084-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2LA5F4J2SLVEY6FKG6O3LFDSA2N3OMZH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2024:0084-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issue:

     Chromium 122.0.6261.128 (boo#1221335)

  * CVE-2024-2400: Use after free in Performance Manager


     Chromium 122.0.6261.111 (boo#1220131,boo#1220604,boo#1221105)

  * New upstream security release.

  * CVE-2024-2173: Out of bounds memory access in V8.

  * CVE-2024-2174: Inappropriate implementation in V8.

  * CVE-2024-2176: Use after free in FedCM.

     Chromium 122.0.6261.94

  * CVE-2024-1669: Out of bounds memory access in Blink.

  * CVE-2024-1670: Use after free in Mojo.

  * CVE-2024-1671: Inappropriate implementation in Site Isolation.

  * CVE-2024-1672: Inappropriate implementation in Content Security Policy.

  * CVE-2024-1673: Use after free in Accessibility.

  * CVE-2024-1674: Inappropriate implementation in Navigation.

  * CVE-2024-1675: Insufficient policy enforcement in Download.

  * CVE-2024-1676: Inappropriate implementation in Navigation.

  * Type Confusion in V8");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
