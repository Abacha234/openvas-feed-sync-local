# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703231");
  script_cve_id("CVE-2015-0248", "CVE-2015-0251");
  script_tag(name:"creation_date", value:"2015-04-20 22:00:00 +0000 (Mon, 20 Apr 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3231)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3231");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3231");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'subversion' package(s) announced via the DSA-3231 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Subversion, a version control system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-0248

Subversion mod_dav_svn and svnserve were vulnerable to a remotely triggerable assertion DoS vulnerability for certain requests with dynamically evaluated revision numbers.

CVE-2015-0251

Subversion HTTP servers allow spoofing svn:author property values for new revisions via specially crafted v1 HTTP protocol request sequences.

For the stable distribution (wheezy), these problems have been fixed in version 1.6.17dfsg-4+deb7u9.

For the upcoming stable distribution (jessie), these problems have been fixed in version 1.8.10-6.

For the unstable distribution (sid), these problems have been fixed in version 1.8.10-6.

We recommend that you upgrade your subversion packages.");

  script_tag(name:"affected", value:"'subversion' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);