# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891604");
  script_tag(name:"creation_date", value:"2018-12-10 23:00:00 +0000 (Mon, 10 Dec 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-1604)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1604");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1604");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lxml' package(s) announced via the DLA-1604 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a XSS injection vulnerability in the LXML HTML/XSS manipulation library for Python.

LXML did not remove 'javascript:' URLs that used escaping such as j a v a s c r i p t. This is a similar issue to CVE-2014-3146.

For Debian 8 Jessie, this issue has been fixed in lxml version 3.4.0-1+deb8u1.

We recommend that you upgrade your lxml packages.");

  script_tag(name:"affected", value:"'lxml' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);