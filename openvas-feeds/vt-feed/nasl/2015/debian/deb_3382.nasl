# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703382");
  script_cve_id("CVE-2014-8958", "CVE-2014-9218", "CVE-2015-2206", "CVE-2015-3902", "CVE-2015-3903", "CVE-2015-6830", "CVE-2015-7873");
  script_tag(name:"creation_date", value:"2015-10-27 23:00:00 +0000 (Tue, 27 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3382)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3382");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3382");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DSA-3382 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been fixed in phpMyAdmin, the web administration tool for MySQL.

CVE-2014-8958 (Wheezy only) Multiple cross-site scripting (XSS) vulnerabilities.

CVE-2014-9218 (Wheezy only) Denial of service (resource consumption) via a long password.

CVE-2015-2206

Risk of BREACH attack due to reflected parameter.

CVE-2015-3902

XSRF/CSRF vulnerability in phpMyAdmin setup.

CVE-2015-3903 (Jessie only) Vulnerability allowing man-in-the-middle attack on API call to GitHub.

CVE-2015-6830 (Jessie only) Vulnerability that allows bypassing the reCaptcha test.

CVE-2015-7873 (Jessie only) Content spoofing vulnerability when redirecting user to an external site.

For the oldstable distribution (wheezy), these problems have been fixed in version 4:3.4.11.1-2+deb7u2.

For the stable distribution (jessie), these problems have been fixed in version 4:4.2.12-2+deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 4:4.5.1-1.

We recommend that you upgrade your phpmyadmin packages.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);