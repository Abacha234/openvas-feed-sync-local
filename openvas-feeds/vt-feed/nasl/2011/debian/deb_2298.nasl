# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70235");
  script_cve_id("CVE-2011-3192");
  script_tag(name:"creation_date", value:"2011-09-21 03:47:11 +0000 (Wed, 21 Sep 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2298)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2298");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2298");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2' package(s) announced via the DSA-2298 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two issues have been found in the Apache HTTPD web server:

CVE-2011-3192

A vulnerability has been found in the way the multiple overlapping ranges are handled by the Apache HTTPD server. This vulnerability allows an attacker to cause Apache HTTPD to use an excessive amount of memory, causing a denial of service.

CVE-2010-1452

A vulnerability has been found in mod_dav that allows an attacker to cause a daemon crash, causing a denial of service. This issue only affects the Debian 5.0 oldstable/lenny distribution.

For the oldstable distribution (lenny), these problems have been fixed in version 2.2.9-10+lenny11.

For the stable distribution (squeeze), this problem has been fixed in version 2.2.16-6+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in version 2.2.19-3.

For the unstable distribution (sid), this problem has been fixed in version 2.2.19-3.

We recommend that you upgrade your apache2 packages.

This update also contains updated apache2-mpm-itk packages which have been recompiled against the updated apache2 packages. The new version number for the oldstable distribution is 2.2.6-02-1+lenny6. In the stable distribution, apache2-mpm-itk has the same version number as apache2.");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);