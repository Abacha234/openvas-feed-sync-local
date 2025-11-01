# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703380");
  script_cve_id("CVE-2015-7803", "CVE-2015-7804");
  script_tag(name:"creation_date", value:"2015-10-26 23:00:00 +0000 (Mon, 26 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3380)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3380");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3380");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-3380 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were found in PHP, a general-purpose scripting language commonly used for web application development.

CVE-2015-7803

The phar extension could crash with a NULL pointer dereference when processing tar archives containing links referring to non-existing files. This could lead to a denial of service.

CVE-2015-7804

The phar extension does not correctly process directory entries found in archive files with the name '/', leading to a denial of service and, potentially, information disclosure.

The update for Debian stable (jessie) contains additional bug fixes from PHP upstream version 5.6.14, as described in the upstream changelog:


Note to users of the oldstable distribution (wheezy): PHP 5.4 has reached end-of-life on September 14th, 2015. As a result, there will be no more new upstream releases. The security support of PHP 5.4 in Debian oldstable (wheezy) will be best effort only, and you are strongly advised to upgrade to latest Debian stable release (jessie), which includes PHP 5.6.

For the oldstable distribution (wheezy), these problems have been fixed in version 5.4.45-0+deb7u2.

For the stable distribution (jessie), these problems have been fixed in version 5.6.14+dfsg-0+deb8u1.

For the testing distribution (stretch) and the unstable distribution (sid), these problems have been fixed in version 5.6.14+dfsg-1.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);