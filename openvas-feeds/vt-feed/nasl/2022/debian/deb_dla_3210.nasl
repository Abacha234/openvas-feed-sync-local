# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893210");
  script_cve_id("CVE-2021-40401", "CVE-2021-40403");
  script_tag(name:"creation_date", value:"2022-11-29 02:00:13 +0000 (Tue, 29 Nov 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-31 18:10:00 +0000 (Tue, 31 May 2022)");

  script_name("Debian: Security Advisory (DLA-3210)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3210");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3210");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gerbv' package(s) announced via the DLA-3210 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in gerbv, a Gerber file viewer. Most Printed Circuit Board (PCB) design programs can export data to a Gerber file.

CVE-2021-40401: A use-after-free vulnerability existed in the RS-274X aperture definition tokenization functionality. A specially-crafted gerber file could have led to code execution.

CVE-2021-40403: An information disclosure vulnerability existed in the pick-and-place rotation parsing functionality. A specially-crafted pick-and-place file could have exploited the missing initialization of a structure in order to leak memory contents.

For Debian 10 Buster, these problems have been fixed in version 2.7.0-1+deb10u2.

We recommend that you upgrade your gerbv packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'gerbv' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);