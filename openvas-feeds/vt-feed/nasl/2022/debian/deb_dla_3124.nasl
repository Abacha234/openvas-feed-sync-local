# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893124");
  script_cve_id("CVE-2022-32886", "CVE-2022-32888", "CVE-2022-32923", "CVE-2022-42863", "CVE-2023-25358", "CVE-2023-25360", "CVE-2023-25361", "CVE-2023-25362", "CVE-2023-25363");
  script_tag(name:"creation_date", value:"2022-09-30 01:00:07 +0000 (Fri, 30 Sep 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-20 02:19:00 +0000 (Tue, 20 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3124)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3124");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3124");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/webkit2gtk");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webkit2gtk' package(s) announced via the DLA-3124 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the WebKitGTK web engine:

CVE-2022-32886

P1umer, afang5472 and xmzyshypnc discovered that processing maliciously crafted web content may lead to arbitrary code execution

For Debian 10 buster, this problem has been fixed in version 2.38.0-1~deb10u1.

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