# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703244");
  script_cve_id("CVE-2015-3011", "CVE-2015-3012", "CVE-2015-3013");
  script_tag(name:"creation_date", value:"2015-05-01 22:00:00 +0000 (Fri, 01 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3244)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3244");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3244");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'owncloud' package(s) announced via the DSA-3244 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in ownCloud, a cloud storage web service for files, music, contacts, calendars and many more.

CVE-2015-3011

Hugh Davenport discovered that the contacts application shipped with ownCloud is vulnerable to multiple stored cross-site scripting attacks. This vulnerability is effectively exploitable in any browser.

CVE-2015-3012

Roy Jansen discovered that the documents application shipped with ownCloud is vulnerable to multiple stored cross-site scripting attacks. This vulnerability is not exploitable in browsers that support the current CSP standard.

CVE-2015-3013

Lukas Reschke discovered a blacklist bypass vulnerability, allowing authenticated remote attackers to bypass the file blacklist and upload files such as the .htaccess files. An attacker could leverage this bypass by uploading a .htaccess and execute arbitrary PHP code if the /data/ directory is stored inside the web root and a web server that interprets .htaccess files is used. On default Debian installations the data directory is outside of the web root and thus this vulnerability is not exploitable by default.

For the stable distribution (jessie), these problems have been fixed in version 7.0.4+dfsg-4~deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 7.0.4+dfsg-3.

For the unstable distribution (sid), these problems have been fixed in version 7.0.4+dfsg-3.

We recommend that you upgrade your owncloud packages.");

  script_tag(name:"affected", value:"'owncloud' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);