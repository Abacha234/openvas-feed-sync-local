# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886289");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2022-38223", "CVE-2023-38252", "CVE-2023-38253", "CVE-2023-4255");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 19:20:24 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:03 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for w3m (FEDORA-2024-aeb75f8b5b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-aeb75f8b5b");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AULOBQJLXE2KCT5UVQMKGEFL4GFIAOED");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'w3m'
  package(s) announced via the FEDORA-2024-aeb75f8b5b advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The w3m program is a pager (or text file viewer) that can also be used
as a text-mode Web browser. W3m features include the following: when
reading an HTML document, you can follow links and view images using
an external image viewer, its internet message mode determines the
type of document from the header, if the Content-Type field of the
document is text/html.");

  script_tag(name:"affected", value:"'w3m' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
