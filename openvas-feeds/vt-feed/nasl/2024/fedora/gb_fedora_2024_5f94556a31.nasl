# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886296");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:35 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for libreoffice (FEDORA-2024-5f94556a31)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-5f94556a31");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SOSAEVZSJFWV33IFVQB7ZTMPNYZPUXJH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice'
  package(s) announced via the FEDORA-2024-5f94556a31 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LibreOffice is an Open Source, community-developed, office productivity suite.
It includes the key desktop applications, such as a word processor,
spreadsheet, presentation manager, formula editor and drawing program, with a
user interface and feature set similar to other office suites.  Sophisticated
and flexible, LibreOffice also works transparently with a variety of file
formats, including Microsoft Office File Formats.");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
