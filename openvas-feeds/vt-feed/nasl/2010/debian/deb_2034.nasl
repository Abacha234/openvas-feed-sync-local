# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67338");
  script_cve_id("CVE-2008-7251", "CVE-2008-7252", "CVE-2009-4605");
  script_tag(name:"creation_date", value:"2010-05-04 03:52:15 +0000 (Tue, 04 May 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2034");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2034");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DSA-2034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in phpMyAdmin, a tool to administer MySQL over the web. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-7251

phpMyAdmin may create a temporary directory, if the configured directory does not exist yet, with insecure filesystem permissions.

CVE-2008-7252

phpMyAdmin uses predictable filenames for temporary files, which may lead to a local denial of service attack or privilege escalation.

CVE-2009-4605

The setup.php script shipped with phpMyAdmin may unserialize untrusted data, allowing for cross site request forgery.

For the stable distribution (lenny), these problems have been fixed in version phpmyadmin 2.11.8.1-5+lenny4.

For the unstable distribution (sid), these problems have been fixed in version 3.2.4-1.

We recommend that you upgrade your phpmyadmin package.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);