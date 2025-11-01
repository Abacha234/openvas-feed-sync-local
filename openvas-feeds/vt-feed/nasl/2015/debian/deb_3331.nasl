# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703331");
  script_cve_id("CVE-2015-3184", "CVE-2015-3187");
  script_tag(name:"creation_date", value:"2015-08-09 22:00:00 +0000 (Sun, 09 Aug 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3331)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3331");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3331");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'subversion' package(s) announced via the DSA-3331 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been found in the server components of the version control system subversion.

CVE-2015-3184

Subversion's mod_authz_svn does not properly restrict anonymous access in some mixed anonymous/authenticated environments when using Apache httpd 2.4. The result is that anonymous access may be possible to files for which only authenticated access should be possible. This issue does not affect the oldstable distribution (wheezy) because it only contains Apache httpd 2.2.

CVE-2015-3187

Subversion servers, both httpd and svnserve, will reveal some paths that should be hidden by path-based authz. When a node is copied from an unreadable location to a readable location the unreadable path may be revealed. This vulnerability only reveals the path, it does not reveal the contents of the path.

For the oldstable distribution (wheezy), this problem has been fixed in version 1.6.17dfsg-4+deb7u10.

For the stable distribution (jessie), these problems have been fixed in version 1.8.10-6+deb8u1.

For the testing distribution (stretch), these problems will be fixed in version 1.9.0-1.

For the unstable distribution (sid), these problems have been fixed in version 1.9.0-1.

We recommend that you upgrade your subversion packages.");

  script_tag(name:"affected", value:"'subversion' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);