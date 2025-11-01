# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893274");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-42852", "CVE-2022-42856", "CVE-2022-42867", "CVE-2022-46692", "CVE-2022-46698", "CVE-2022-46699", "CVE-2022-46700");
  script_tag(name:"creation_date", value:"2023-01-20 02:00:09 +0000 (Fri, 20 Jan 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-21 06:15:00 +0000 (Wed, 21 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3274)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3274");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3274");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/webkit2gtk");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webkit2gtk' package(s) announced via the DLA-3274 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the WebKitGTK web engine:

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

For Debian 10 buster, these problems have been fixed in version 2.38.3-1~deb10u1.

We recommend that you upgrade your webkit2gtk packages.

For the detailed security status of webkit2gtk please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);