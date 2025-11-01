# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703042");
  script_cve_id("CVE-2014-7204");
  script_tag(name:"creation_date", value:"2014-10-03 22:00:00 +0000 (Fri, 03 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3042)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3042");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3042");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exuberant-ctags' package(s) announced via the DSA-3042 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefano Zacchiroli discovered a vulnerability in exuberant-ctags, a tool to build tag file indexes of source code definitions: Certain JavaScript files cause ctags to enter an infinite loop until it runs out of disk space, resulting in denial of service.

For the stable distribution (wheezy), this problem has been fixed in version 1:5.9~svn20110310-4+deb7u1.

For the testing distribution (jessie), this problem has been fixed in version 1:5.9~svn20110310-8.

For the unstable distribution (sid), this problem has been fixed in version 1:5.9~svn20110310-8.

We recommend that you upgrade your exuberant-ctags packages.");

  script_tag(name:"affected", value:"'exuberant-ctags' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);