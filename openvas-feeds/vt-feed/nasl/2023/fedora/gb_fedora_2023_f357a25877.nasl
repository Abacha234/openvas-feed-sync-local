# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884832");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-36328");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-06 00:05:00 +0000 (Wed, 06 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-18 01:14:31 +0000 (Mon, 18 Sep 2023)");
  script_name("Fedora: Security Advisory for libtommath (FEDORA-2023-f357a25877)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-f357a25877");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6ZUPWZGPFJ4JOI2NIP7YLRKZD5YXQTBK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtommath'
  package(s) announced via the FEDORA-2023-f357a25877 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A free open source portable number theoretic multiple-precision integer library
written entirely in C. (phew!). The library is designed to provide a simple to
work with API that provides fairly efficient routines that build out of the box
without configuration.");

  script_tag(name:"affected", value:"'libtommath' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
