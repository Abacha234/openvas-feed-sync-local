# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703160");
  script_cve_id("CVE-2015-0255");
  script_tag(name:"creation_date", value:"2015-02-10 23:00:00 +0000 (Tue, 10 Feb 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3160)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3160");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3160");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xorg-server' package(s) announced via the DSA-3160 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Olivier Fourdan discovered that missing input validation in the Xserver's handling of XkbSetGeometry requests may result in an information leak or denial of service.

For the stable distribution (wheezy), this problem has been fixed in version 2:1.12.4-6+deb7u6.

For the unstable distribution (sid), this problem has been fixed in version 2:1.16.4-1.

We recommend that you upgrade your xorg-server packages.");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);