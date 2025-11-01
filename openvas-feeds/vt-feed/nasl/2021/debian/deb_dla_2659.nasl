# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892659");
  script_cve_id("CVE-2018-10196", "CVE-2020-18032");
  script_tag(name:"creation_date", value:"2021-05-14 03:03:24 +0000 (Fri, 14 May 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-03 06:15:00 +0000 (Sat, 03 Jul 2021)");

  script_name("Debian: Security Advisory (DLA-2659)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2659");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2659");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/graphviz");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphviz' package(s) announced via the DLA-2659 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-10196

NULL pointer dereference vulnerability in the rebuild_vlists function in lib/dotgen/conc.c in the dotgen library allows remote attackers to cause a denial of service (application crash) via a crafted file.

CVE-2020-18032

A buffer overflow was discovered in Graphviz, which could potentially result in the execution of arbitrary code when processing a malformed file.

For Debian 9 stretch, these problems have been fixed in version 2.38.0-17+deb9u1.

We recommend that you upgrade your graphviz packages.

For the detailed security status of graphviz please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'graphviz' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);