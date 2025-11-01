# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887043");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-49084", "CVE-2023-49086", "CVE-2023-49085", "CVE-2023-49088", "CVE-2023-50250", "CVE-2023-51448", "CVE-2024-34340", "CVE-2024-29894", "CVE-2024-31458", "CVE-2024-31459", "CVE-2024-31460", "CVE-2024-31443", "CVE-2024-31444", "CVE-2024-31445", "CVE-2024-25641");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-22 17:15:09 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-06-07 06:35:27 +0000 (Fri, 07 Jun 2024)");
  script_name("Fedora: Security Advisory for cacti-spine (FEDORA-2024-27a594f71d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-27a594f71d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RBEOAFKRARQHTDIYSL723XAFJ2Q6624X");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti-spine'
  package(s) announced via the FEDORA-2024-27a594f71d advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Spine is a supplemental poller for Cacti that makes use of pthreads to achieve
excellent performance.");

  script_tag(name:"affected", value:"'cacti-spine' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
