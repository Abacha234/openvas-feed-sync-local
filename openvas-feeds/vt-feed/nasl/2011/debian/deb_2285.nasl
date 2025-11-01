# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70059");
  script_cve_id("CVE-2011-2703", "CVE-2011-2704");
  script_tag(name:"creation_date", value:"2011-08-07 15:37:07 +0000 (Sun, 07 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2285)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2285");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2285");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mapserver' package(s) announced via the DSA-2285 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in mapserver, a CGI-based web framework to publish spatial data and interactive mapping applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2011-2703

Several instances of insufficient escaping of user input, leading to SQL injection attacks via OGC filter encoding (in WMS, WFS, and SOS filters).

CVE-2011-2704

Missing length checks in the processing of OGC filter encoding that can lead to stack-based buffer overflows and the execution of arbitrary code.

For the oldstable distribution (lenny), these problems have been fixed in version 5.0.3-3+lenny7.

For the stable distribution (squeeze), these problems have been fixed in version 5.6.5-2+squeeze2.

For the testing (squeeze) and unstable (sid) distributions, these problems will be fixed soon.

We recommend that you upgrade your mapserver packages.");

  script_tag(name:"affected", value:"'mapserver' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);