# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703257");
  script_cve_id("CVE-2014-9462");
  script_tag(name:"creation_date", value:"2015-05-10 22:00:00 +0000 (Sun, 10 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3257)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3257");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3257");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mercurial' package(s) announced via the DSA-3257 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jesse Hertz of Matasano Security discovered that Mercurial, a distributed version control system, is prone to a command injection vulnerability via a crafted repository name in a clone command.

For the oldstable distribution (wheezy), this problem has been fixed in version 2.2.2-4+deb7u1. This update also includes a fix for CVE-2014-9390 previously scheduled for the next wheezy point release.

For the stable distribution (jessie), this problem has been fixed in version 3.1.2-2+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 3.4-1.

We recommend that you upgrade your mercurial packages.");

  script_tag(name:"affected", value:"'mercurial' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);