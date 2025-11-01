# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833019");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-0741", "CVE-2024-0742", "CVE-2024-0746", "CVE-2024-0747", "CVE-2024-0749", "CVE-2024-0750", "CVE-2024-0751", "CVE-2024-0753", "CVE-2024-0755");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 22:47:49 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:55:24 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for MozillaFirefox (SUSE-SU-2024:0229-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0229-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FYATJVAUGXYP5MK2LKW5JJLVVXZWXCGL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the SUSE-SU-2024:0229-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

  Update to Firefox Extended Support Release 115.7.0 ESR (MFSA2024-02)
  (bsc#1218955):

  * CVE-2024-0741: Out of bounds write in ANGLE

  * CVE-2024-0742: Failure to update user input timestamp

  * CVE-2024-0746: Crash when listing printers on Linux

  * CVE-2024-0747: Bypass of Content Security Policy when directive unsafe-
      inline was set

  * CVE-2024-0749: Phishing site popup could show local origin in address bar

  * CVE-2024-0750: Potential permissions request bypass via clickjacking

  * CVE-2024-0751: Privilege escalation through devtools

  * CVE-2024-0753: HSTS policy on subdomain could bypass policy of upper domain

  * CVE-2024-0755: Memory safety bugs fixed in Firefox 122, Firefox ESR 115.7,
      and Thunderbird 115.7

  ##");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
