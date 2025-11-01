# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64251");
  script_cve_id("CVE-2009-1195");
  script_tag(name:"creation_date", value:"2009-06-23 13:49:15 +0000 (Tue, 23 Jun 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1816)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1816");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1816");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2' package(s) announced via the DSA-1816 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Apache web server did not properly handle the 'Options=' parameter to the AllowOverride directive:

In the stable distribution (lenny), local users could (via .htaccess) enable script execution in Server Side Includes even in configurations where the AllowOverride directive contained only Options=IncludesNoEXEC.

In the oldstable distribution (etch), local users could (via .htaccess) enable script execution in Server Side Includes and CGI script execution in configurations where the AllowOverride directive contained any 'Options=' value.

The oldstable distribution (etch), this problem has been fixed in version 2.2.3-4+etch8.

For the stable distribution (lenny), this problem has been fixed in version 2.2.9-10+lenny3.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem will be fixed in version 2.2.11-6.

This advisory also provides updated apache2-mpm-itk packages which have been recompiled against the new apache2 packages (except for the s390 architecture where updated packages will follow shortly).

We recommend that you upgrade your apache2 packages.");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);