# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887222");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-3727");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-06-11 04:08:04 +0000 (Tue, 11 Jun 2024)");
  script_name("Fedora: Security Advisory for podman-tui (FEDORA-2024-e383f723a9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e383f723a9");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DTOMYERG5ND4QFDHC4ZSGCED3T3ESRSC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman-tui'
  package(s) announced via the FEDORA-2024-e383f723a9 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"podman-tui is a terminal user interface for Podman v4 and v5.
podman-tui is using podman.socket service to communicate with podman environment
and SSH to connect to remote podman machines.");

  script_tag(name:"affected", value:"'podman-tui' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
