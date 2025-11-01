# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60212");
  script_cve_id("CVE-2007-2450", "CVE-2008-0128");
  script_tag(name:"creation_date", value:"2008-01-31 15:11:48 +0000 (Thu, 31 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1468)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1468");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1468");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat5.5' package(s) announced via the DSA-1468 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Tomcat servlet and JSP engine. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0128

Olaf Kock discovered that HTTPS encryption was insufficiently enforced for single-sign-on cookies, which could result in information disclosure.

CVE-2007-2450

It was discovered that the Manager and Host Manager web applications performed insufficient input sanitising, which could lead to cross site scripting.

This update also adapts the tomcat5.5-webapps package to the tightened JULI permissions introduced in the previous tomcat5.5 DSA. However, it should be noted, that the tomcat5.5-webapps is for demonstration and documentation purposes only and should not be used for production systems.

The old stable distribution (sarge) doesn't contain tomcat5.5.

For the stable distribution (etch), these problems have been fixed in version 5.5.20-2etch2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your tomcat5.5 packages.");

  script_tag(name:"affected", value:"'tomcat5.5' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);