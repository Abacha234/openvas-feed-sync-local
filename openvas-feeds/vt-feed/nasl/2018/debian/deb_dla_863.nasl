# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890863");
  script_cve_id("CVE-2017-7178");
  script_tag(name:"creation_date", value:"2018-01-11 23:00:00 +0000 (Thu, 11 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-08 17:40:00 +0000 (Wed, 08 Jul 2020)");

  script_name("Debian: Security Advisory (DLA-863)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-863");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-863");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'deluge' package(s) announced via the DLA-863 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a cross-site request forgery vulnerability in the WebUI component of the deluge Bittorrent client.

For Debian 7 Wheezy, this issue has been fixed in deluge version 1.3.3-2+nmu1+deb7u1.

We recommend that you upgrade your deluge packages.");

  script_tag(name:"affected", value:"'deluge' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);