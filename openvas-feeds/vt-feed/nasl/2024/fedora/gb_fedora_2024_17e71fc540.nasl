# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887239");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-3049");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-11 17:54:22 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-16 04:08:56 +0000 (Sun, 16 Jun 2024)");
  script_name("Fedora: Security Advisory for booth (FEDORA-2024-17e71fc540)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-17e71fc540");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KPK5BHYOB7CFFRQAN55YV5LH44PWHMQD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'booth'
  package(s) announced via the FEDORA-2024-17e71fc540 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Booth manages tickets which authorize cluster sites located
in geographically dispersed locations to run resources.
It facilitates support of geographically distributed
clustering in Pacemaker.");

  script_tag(name:"affected", value:"'booth' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
