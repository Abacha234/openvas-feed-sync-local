# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702639");
  script_cve_id("CVE-2013-1635", "CVE-2013-1643", "CVE-2013-1824");
  script_tag(name:"creation_date", value:"2013-03-04 23:00:00 +0000 (Mon, 04 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2639)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2639");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2639");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-2639 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in PHP, the web scripting language. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2013-1635

If a PHP application accepted untrusted SOAP object input remotely from clients, an attacker could read system files readable for the webserver.

CVE-2013-1643

The soap.wsdl_cache_dir function did not take PHP open_basedir restrictions into account. Note that Debian advises against relying on open_basedir restrictions for security.

For the stable distribution (squeeze), these problems have been fixed in version 5.3.3-7+squeeze15.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 5.4.4-14.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);