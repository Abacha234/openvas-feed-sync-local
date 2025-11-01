# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703708");
  script_tag(name:"creation_date", value:"2016-11-14 12:29:49 +0000 (Mon, 14 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3708)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3708");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3708");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mat' package(s) announced via the DSA-3708 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hartmut Goebel discovered that MAT, a toolkit to anonymise/remove metadata from files did not remove metadata from images embededed in PDF documents.

For the stable distribution (jessie), this problem has been fixed in version 0.5.2-3+deb8u1. This update disables PDF support in MAT entirely.

We recommend that you upgrade your mat packages.");

  script_tag(name:"affected", value:"'mat' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);