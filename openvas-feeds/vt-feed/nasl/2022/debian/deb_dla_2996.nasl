# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892996");
  script_cve_id("CVE-2017-9527", "CVE-2018-10191", "CVE-2018-11743", "CVE-2018-12249", "CVE-2018-14337", "CVE-2020-15866");
  script_tag(name:"creation_date", value:"2022-05-07 01:00:11 +0000 (Sat, 07 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-23 19:45:00 +0000 (Thu, 23 Jul 2020)");

  script_name("Debian: Security Advisory (DLA-2996)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2996");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2996");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mruby");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mruby' package(s) announced via the DLA-2996 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brief introduction

CVE-2017-9527

Description

CVE-2018-10191

Description

CVE-2018-11743

Description

CVE-2018-12249

Description

CVE-2018-14337

Description

CVE-2020-15866

Description

For Debian 9 stretch, these problems have been fixed in version 1.2.0+20161228+git30d5424a-1+deb9u1.

We recommend that you upgrade your mruby packages.

For the detailed security status of mruby please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mruby' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);