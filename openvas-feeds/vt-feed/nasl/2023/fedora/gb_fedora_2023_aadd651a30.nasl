# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884807");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-33551", "CVE-2023-33552");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-12 14:27:00 +0000 (Mon, 12 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:29 +0000 (Sat, 16 Sep 2023)");
  script_name("Fedora: Security Advisory for erofs-utils (FEDORA-2023-aadd651a30)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-aadd651a30");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IGGIYW7PHYQM2NPYCJPSPSLULLD2P2PE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'erofs-utils'
  package(s) announced via the FEDORA-2023-aadd651a30 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"EROFS stands for Enhanced Read-Only File System.  It aims to be a general
read-only file system solution for various use cases instead of just focusing
on saving storage space without considering runtime performance.

This package includes tools to create, check, and extract EROFS images.");

  script_tag(name:"affected", value:"'erofs-utils' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
