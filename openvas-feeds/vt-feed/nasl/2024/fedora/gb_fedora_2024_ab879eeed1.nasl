# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885655");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-52339");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-22 15:48:15 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-02-05 02:03:21 +0000 (Mon, 05 Feb 2024)");
  script_name("Fedora: Security Advisory for libebml (FEDORA-2024-ab879eeed1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ab879eeed1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BJUXVOIRWPP7OFYUKQZDNJTSLWCPIZBH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libebml'
  package(s) announced via the FEDORA-2024-ab879eeed1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Extensible Binary Meta Language access library A library for reading
and writing files with the Extensible Binary Meta Language, a binary
pendant to XML.");

  script_tag(name:"affected", value:"'libebml' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
