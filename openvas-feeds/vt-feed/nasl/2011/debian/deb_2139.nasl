# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68980");
  script_cve_id("CVE-2010-4329", "CVE-2010-4480", "CVE-2010-4481");
  script_tag(name:"creation_date", value:"2011-03-07 15:04:02 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2139)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2139");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2139");
  script_xref(name:"URL", value:"https://www.debian.org/security/");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DSA-2139 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in phpMyAdmin, a tool to administer MySQL over the web. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-4329

Cross site scripting was possible in search, that allowed a remote attacker to inject arbitrary web script or HTML.

CVE-2010-4480

Cross site scripting was possible in errors, that allowed a remote attacker to inject arbitrary web script or HTML.

CVE-2010-4481

Display of PHP's phpinfo() function was available to world, but only if this functionality had been enabled (defaults to off). This may leak some information about the host system.

For the stable distribution (lenny), these problems have been fixed in version 2.11.8.1-5+lenny7.

For the testing (squeeze) and unstable distribution (sid), these problems have been fixed in version 3.3.7-3.

We recommend that you upgrade your phpmyadmin package.

Further information about Debian Security Advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);