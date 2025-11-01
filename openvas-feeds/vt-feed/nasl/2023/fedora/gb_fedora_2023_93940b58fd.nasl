# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885471");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-6377", "CVE-2023-6478");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-21 17:18:00 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-19 02:15:56 +0000 (Tue, 19 Dec 2023)");
  script_name("Fedora: Security Advisory for xorg-x11-server-Xwayland (FEDORA-2023-93940b58fd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-93940b58fd");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7PP47YXKM5ETLCYEF6473R3VFCJ6QT2S");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server-Xwayland'
  package(s) announced via the FEDORA-2023-93940b58fd advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xwayland is an X server for running X clients under Wayland.");

  script_tag(name:"affected", value:"'xorg-x11-server-Xwayland' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
