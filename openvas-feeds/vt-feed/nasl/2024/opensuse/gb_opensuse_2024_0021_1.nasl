# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833285");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-22368");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 14:58:04 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:51:41 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for perl (openSUSE-SU-2024:0021)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0021");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EHHPL7IKGNQCRM3NOTRZRDYWT4OKW47L");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for perl-Spreadsheet-ParseXLSX fixes the following issues:

  - Fix die message in parse()

  - Cannot open password protected SHA1 encrypted files. doy#68

  - use date format detection based on Spreadsheet::XLSX

  - Add rudimentary support for hyperlinks in cells

     0.28:

  - CVE-2024-22368: out-of-memory condition during parsing of a crafted XLSX
       document (boo#1218651)

  - Fix possible memory bomb as reported in
       lsx_bomb.md

  - Updated Dist::Zilla configuration fixing deprecation warnings");

  script_tag(name:"affected", value:"'perl' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
