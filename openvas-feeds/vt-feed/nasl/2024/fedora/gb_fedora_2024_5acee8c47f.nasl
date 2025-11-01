# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887235");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-5830", "CVE-2024-5831", "CVE-2024-5832", "CVE-2024-5833", "CVE-2024-5834", "CVE-2024-5835", "CVE-2024-5836", "CVE-2024-5837", "CVE-2024-5838", "CVE-2024-5839", "CVE-2024-5840", "CVE-2024-5841", "CVE-2024-5842", "CVE-2024-5843", "CVE-2024-5844", "CVE-2024-5845", "CVE-2024-5846", "CVE-2024-5847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-20 13:05:43 +0000 (Thu, 20 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-15 04:07:26 +0000 (Sat, 15 Jun 2024)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2024-5acee8c47f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-5acee8c47f");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7VXA32LXMNK3DSK3JBRLTBPFUH7LTODU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2024-5acee8c47f advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
