# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702637");
  script_cve_id("CVE-2012-3499", "CVE-2012-4558", "CVE-2013-1048");
  script_tag(name:"creation_date", value:"2013-03-03 23:00:00 +0000 (Sun, 03 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2637)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2637");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2637");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2' package(s) announced via the DSA-2637 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Apache HTTPD server.

CVE-2012-3499

The modules mod_info, mod_status, mod_imagemap, mod_ldap, and mod_proxy_ftp did not properly escape hostnames and URIs in HTML output, causing cross site scripting vulnerabilities.

CVE-2012-4558

Mod_proxy_balancer did not properly escape hostnames and URIs in its balancer-manager interface, causing a cross site scripting vulnerability.

CVE-2013-1048

Hayawardh Vijayakumar noticed that the apache2ctl script created the lock directory in an unsafe manner, allowing a local attacker to gain elevated privileges via a symlink attack. This is a Debian specific issue.

For the stable distribution (squeeze), these problems have been fixed in version 2.2.16-6+squeeze11.

For the testing distribution (wheezy), these problems will be fixed in version 2.2.22-13.

For the unstable distribution (sid), these problems will be fixed in version 2.2.22-13.

We recommend that you upgrade your apache2 packages.");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);