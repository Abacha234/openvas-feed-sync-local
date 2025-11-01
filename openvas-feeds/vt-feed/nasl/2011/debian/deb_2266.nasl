# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69973");
  script_cve_id("CVE-2010-2531", "CVE-2011-0420", "CVE-2011-0421", "CVE-2011-0708", "CVE-2011-1153", "CVE-2011-1466", "CVE-2011-1471", "CVE-2011-2202");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2266)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2266");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2266");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-2266 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in PHP, which could lead to denial of service or potentially the execution of arbitrary code.

CVE-2010-2531

An information leak was found in the var_export() function.

CVE-2011-0421

The Zip module could crash.

CVE-2011-0708

An integer overflow was discovered in the Exif module.

CVE-2011-1466

An integer overflow was discovered in the Calendar module.

CVE-2011-1471

The Zip module was prone to denial of service through malformed archives.

CVE-2011-2202

Path names in form based file uploads (RFC 1867) were incorrectly validated.

This update also fixes two bugs, which are not treated as security issues, but fixed nonetheless, see README.Debian.security for details on the scope of security support for PHP (CVE-2011-0420, CVE-2011-1153).

For the oldstable distribution (lenny), these problems have been fixed in version 5.2.6.dfsg.1-1+lenny12.

For the stable distribution (squeeze), these problems have been fixed in version 5.3.3-7+squeeze3.

For the unstable distribution (sid), these problems have been fixed in version 5.3.6-12.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);