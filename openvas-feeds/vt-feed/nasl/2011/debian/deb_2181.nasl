# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69116");
  script_cve_id("CVE-2011-0715");
  script_tag(name:"creation_date", value:"2011-03-09 04:54:11 +0000 (Wed, 09 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2181)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2181");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2181");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'subversion' package(s) announced via the DSA-2181 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Philip Martin discovered that HTTP-based Subversion servers crash when processing lock requests on repositories which support unauthenticated read access.

For the oldstable distribution (lenny), this problem has been fixed in version 1.5.1dfsg1-6.

For the stable distribution (squeeze), this problem has been fixed in version 1.6.12dfsg-5.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem will be fixed in version 1.6.16dfsg-1.

We recommend that you upgrade your subversion packages.");

  script_tag(name:"affected", value:"'subversion' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);