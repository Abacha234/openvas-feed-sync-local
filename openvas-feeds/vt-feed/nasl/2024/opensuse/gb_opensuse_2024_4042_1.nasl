# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856734");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-10389", "CVE-2024-10975", "CVE-2024-45794", "CVE-2024-48057", "CVE-2024-51735", "CVE-2024-51744", "CVE-2024-51746");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-11-23 05:00:27 +0000 (Sat, 23 Nov 2024)");
  script_name("openSUSE: Security Advisory for govulncheck (SUSE-SU-2024:4042-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4042-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OTXFFCDR2Z3RCPXDHKQF3TEWFZIPUYSQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck'
  package(s) announced via the SUSE-SU-2024:4042-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

  * Update to version 0.0.20241112T145010 2024-11-12T14:50:10Z. Refs
      jsc#PED-11136 Go CVE Numbering Authority IDs added or updated with aliases:

  * GO-2024-3250 CVE-2024-51744 GHSA-29wx-vh33-7x7r

  * Update to version 0.0.20241108T172500 2024-11-08T17:25:00Z. Refs
      jsc#PED-11136 Go CVE Numbering Authority IDs added or updated with aliases:

  * GO-2024-3260 CVE-2024-45794 GHSA-q78v-cv36-8fxj

  * GO-2024-3262 CVE-2024-10975 GHSA-2w5v-x29g-jw7j

  * Update to version 0.0.20241106T172143 2024-11-06T17:21:43Z. Refs
      jsc#PED-11136 Go CVE Numbering Authority IDs added or updated with aliases:

  * GO-2024-3251 CVE-2024-10389 GHSA-q3rp-vvm7-j8jg

  * GO-2024-3252 CVE-2024-51746 GHSA-8pmp-678w-c8xx

  * GO-2024-3253 CVE-2024-48057 GHSA-ghx4-cgxw-7h9p

  * GO-2024-3254 CVE-2024-51735 GHSA-wvv7-wm5v-w2gv");

  script_tag(name:"affected", value:"'govulncheck' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
