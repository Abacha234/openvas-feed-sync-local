# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705309");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-42852", "CVE-2022-42856", "CVE-2022-42867", "CVE-2022-46692", "CVE-2022-46698", "CVE-2022-46699", "CVE-2022-46700");
  script_tag(name:"creation_date", value:"2023-01-01 02:00:10 +0000 (Sun, 01 Jan 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-21 06:15:00 +0000 (Wed, 21 Dec 2022)");

  script_name("Debian: Security Advisory (DSA-5309)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5309");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5309");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wpewebkit");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpewebkit' package(s) announced via the DSA-5309 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the WPE WebKit web engine:

CVE-2022-42852

hazbinhotel discovered that processing maliciously crafted web content may result in the disclosure of process memory.

CVE-2022-42856

Clement Lecigne discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2022-42867

Maddie Stone discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2022-46692

KirtiKumar Anandrao Ramchandani discovered that processing maliciously crafted web content may bypass Same Origin Policy.

CVE-2022-46698

Dohyun Lee and Ryan Shin discovered that processing maliciously crafted web content may disclose sensitive user information.

CVE-2022-46699

Samuel Gross discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2022-46700

Samuel Gross discovered that processing maliciously crafted web content may lead to arbitrary code execution.

For the stable distribution (bullseye), these problems have been fixed in version 2.38.3-1~deb11u1.

We recommend that you upgrade your wpewebkit packages.

For the detailed security status of wpewebkit please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wpewebkit' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);