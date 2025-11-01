# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891311");
  script_cve_id("CVE-2018-7667");
  script_tag(name:"creation_date", value:"2018-03-26 22:00:00 +0000 (Mon, 26 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-27 13:32:00 +0000 (Tue, 27 Mar 2018)");

  script_name("Debian: Security Advisory (DLA-1311)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1311");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1311");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'adminer' package(s) announced via the DLA-1311 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a server-side request forgery exploit in adminer, a web-based database administration tool.

Adminer allowed unauthenticated connections to be initiated to arbitrary systems and ports which could bypass external firewalls to identify internal hosts or perform port scanning of other servers.

For Debian 7 Wheezy, this issue has been fixed in adminer version 3.3.3-1+deb7u1.

We recommend that you upgrade your adminer packages.");

  script_tag(name:"affected", value:"'adminer' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);