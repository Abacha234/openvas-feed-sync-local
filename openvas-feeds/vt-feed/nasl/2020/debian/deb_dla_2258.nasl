# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892258");
  script_cve_id("CVE-2018-16548", "CVE-2018-6381", "CVE-2018-6484", "CVE-2018-6540", "CVE-2018-6541", "CVE-2018-6869", "CVE-2018-7725", "CVE-2018-7726");
  script_tag(name:"creation_date", value:"2020-06-29 03:00:20 +0000 (Mon, 29 Jun 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-28 15:15:00 +0000 (Sun, 28 Jun 2020)");

  script_name("Debian: Security Advisory (DLA-2258)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2258");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2258");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zziplib' package(s) announced via the DLA-2258 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been fixed in zziplib, a library providing read access on ZIP-archives. They are basically all related to invalid memory access and resulting crash or memory leak.

For Debian 8 Jessie, these problems have been fixed in version 0.13.62-3+deb8u2.

We recommend that you upgrade your zziplib packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'zziplib' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);