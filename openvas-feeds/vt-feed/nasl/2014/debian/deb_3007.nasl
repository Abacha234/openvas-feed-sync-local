# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703007");
  script_cve_id("CVE-2014-5025", "CVE-2014-5026", "CVE-2014-5261", "CVE-2014-5262");
  script_tag(name:"creation_date", value:"2014-08-19 22:00:00 +0000 (Tue, 19 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3007)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3007");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3007");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cacti' package(s) announced via the DSA-3007 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues (cross-site scripting, missing input sanitising and SQL injection) have been discovered in Cacti, a web interface for graphing of monitoring systems.

For the stable distribution (wheezy), these problems have been fixed in version 0.8.8a+dfsg-5+deb7u4.

For the unstable distribution (sid), these problems have been fixed in version 0.8.8b+dfsg-8.

We recommend that you upgrade your cacti packages.");

  script_tag(name:"affected", value:"'cacti' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);