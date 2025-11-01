# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885196");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-29408", "CVE-2023-29407", "CVE-2022-41727");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-07 18:15:00 +0000 (Mon, 07 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-11-05 02:20:51 +0000 (Sun, 05 Nov 2023)");
  script_name("Fedora: Security Advisory for golang-x-image (FEDORA-2023-28cff1a2de)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-28cff1a2de");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XZTEP6JYILRBNDTNWTEQ5D4QUUVQBESK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-x-image'
  package(s) announced via the FEDORA-2023-28cff1a2de advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This package holds supplementary Go image libraries.");

  script_tag(name:"affected", value:"'golang-x-image' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
