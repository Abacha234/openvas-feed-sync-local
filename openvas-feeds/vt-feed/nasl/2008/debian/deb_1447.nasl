# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60102");
  script_cve_id("CVE-2007-3382", "CVE-2007-3385", "CVE-2007-3386", "CVE-2007-5342", "CVE-2007-5461");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1447)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1447");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1447");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat5.5' package(s) announced via the DSA-1447 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Tomcat servlet and JSP engine. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3382

It was discovered that single quotes (') in cookies were treated as a delimiter, which could lead to an information leak.

CVE-2007-3385

It was discovered that the character sequence ' in cookies was handled incorrectly, which could lead to an information leak.

CVE-2007-3386

It was discovered that the host manager servlet performed insufficient input validation, which could lead to a cross-site scripting attack.

CVE-2007-5342

It was discovered that the JULI logging component did not restrict its target path, resulting in potential denial of service through file overwrites.

CVE-2007-5461

It was discovered that the WebDAV servlet is vulnerable to absolute path traversal.

The old stable distribution (sarge) doesn't contain tomcat5.5.

For the stable distribution (etch), these problems have been fixed in version 5.5.20-2etch1.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your tomcat5.5 packages.");

  script_tag(name:"affected", value:"'tomcat5.5' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);