# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71135");
  script_cve_id("CVE-2010-4697", "CVE-2011-1072", "CVE-2011-1092", "CVE-2011-1148", "CVE-2011-1464", "CVE-2011-1467", "CVE-2011-1468", "CVE-2011-1469", "CVE-2011-1470", "CVE-2011-1657", "CVE-2011-3182", "CVE-2011-3267", "CVE-2011-4153", "CVE-2012-0781", "CVE-2012-0788", "CVE-2012-0831");
  script_tag(name:"creation_date", value:"2012-03-12 15:30:50 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2408)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2408");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2408");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-2408 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in PHP, the web scripting language. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2011-1072

It was discovered that insecure handling of temporary files in the PEAR installer could lead to denial of service.

CVE-2011-4153

Maksymilian Arciemowicz discovered that a NULL pointer dereference in the zend_strndup() function could lead to denial of service.

CVE-2012-0781

Maksymilian Arciemowicz discovered that a NULL pointer dereference in the tidy_diagnose() function could lead to denial of service.

CVE-2012-0788

It was discovered that missing checks in the handling of PDORow objects could lead to denial of service.

CVE-2012-0831

It was discovered that the magic_quotes_gpc setting could be disabled remotely.

This update also addresses PHP bugs, which are not treated as security issues in Debian (see README.Debian.security), but which were fixed nonetheless: CVE-2010-4697, CVE-2011-1092, CVE-2011-1148, CVE-2011-1464, CVE-2011-1467 CVE-2011-1468, CVE-2011-1469, CVE-2011-1470, CVE-2011-1657, CVE-2011-3182 CVE-2011-3267

For the stable distribution (squeeze), this problem has been fixed in version 5.3.3-7+squeeze8.

For the unstable distribution (sid), this problem has been fixed in version 5.3.10-1.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);