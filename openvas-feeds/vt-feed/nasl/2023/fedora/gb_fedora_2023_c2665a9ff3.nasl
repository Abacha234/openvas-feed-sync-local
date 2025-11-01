# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885030");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-43115");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-22 17:49:00 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2023-10-17 01:17:13 +0000 (Tue, 17 Oct 2023)");
  script_name("Fedora: Security Advisory for ghostscript (FEDORA-2023-c2665a9ff3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c2665a9ff3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PG5AQV7JOL5TAU76FWPJCMSKO5DREKV5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript'
  package(s) announced via the FEDORA-2023-c2665a9ff3 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This package provides useful conversion utilities based on Ghostscript software,
for converting PS, PDF and other document formats between each other.

Ghostscript is a suite of software providing an interpreter for Adobe Systems&#39,
PostScript (PS) and Portable Document Format (PDF) page description languages.
Its primary purpose includes displaying (rasterization & rendering) and printing
of document pages, as well as conversions between different document formats.");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
