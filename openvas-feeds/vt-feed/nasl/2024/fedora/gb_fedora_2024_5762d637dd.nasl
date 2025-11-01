# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885591");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-6816", "CVE-2024-0229", "CVE-2024-21885", "CVE-2024-21886", "CVE-2024-0408", "CVE-2024-0409");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 18:50:00 +0000 (Fri, 26 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-22 02:02:52 +0000 (Mon, 22 Jan 2024)");
  script_name("Fedora: Security Advisory for xorg-x11-server (FEDORA-2024-5762d637dd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-5762d637dd");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EE4CHGIHDBONTUJERHJY737STGIOBZA7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server'
  package(s) announced via the FEDORA-2024-5762d637dd advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"X.Org X11 X server");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
