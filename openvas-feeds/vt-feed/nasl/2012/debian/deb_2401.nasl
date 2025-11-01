# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70718");
  script_cve_id("CVE-2011-1184", "CVE-2011-2204", "CVE-2011-2526", "CVE-2011-3190", "CVE-2011-3375", "CVE-2011-4858", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064", "CVE-2012-0022");
  script_tag(name:"creation_date", value:"2012-02-12 11:38:55 +0000 (Sun, 12 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2401)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2401");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2401");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat6' package(s) announced via the DSA-2401 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in Tomcat, a servlet and JSP engine:

CVE-2011-1184 CVE-2011-5062 CVE-2011-5063 CVE-2011-5064 The HTTP Digest Access Authentication implementation performed insufficient countermeasures against replay attacks.

CVE-2011-2204

In rare setups passwords were written into a logfile.

CVE-2011-2526

Missing input sanitising in the HTTP APR or HTTP NIO connectors could lead to denial of service.

CVE-2011-3190

AJP requests could be spoofed in some setups.

CVE-2011-3375

Incorrect request caching could lead to information disclosure.

CVE-2011-4858 CVE-2012-0022 This update adds countermeasures against a collision denial of service vulnerability in the Java hashtable implementation and addresses denial of service potentials when processing large amounts of requests.

Additional information can be found at

For the stable distribution (squeeze), this problem has been fixed in version 6.0.35-1+squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 6.0.35-1.

We recommend that you upgrade your tomcat6 packages.");

  script_tag(name:"affected", value:"'tomcat6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);