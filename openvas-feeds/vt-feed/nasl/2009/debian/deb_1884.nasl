# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64869");
  script_cve_id("CVE-2009-2629");
  script_tag(name:"creation_date", value:"2009-09-15 20:46:32 +0000 (Tue, 15 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1884)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1884");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1884");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nginx' package(s) announced via the DSA-1884 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Ries discovered that nginx, a high-performance HTTP server, reverse proxy and IMAP/POP3 proxy server, is vulnerable to a buffer underflow when processing certain HTTP requests. An attacker can use this to execute arbitrary code with the rights of the worker process (www-data on Debian) or possibly perform denial of service attacks by repeatedly crashing worker processes via a specially crafted URL in an HTTP request.

For the oldstable distribution (etch), this problem has been fixed in version 0.4.13-2+etch2.

For the stable distribution (lenny), this problem has been fixed in version 0.6.32-3+lenny2.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 0.7.61-3.

We recommend that you upgrade your nginx packages.");

  script_tag(name:"affected", value:"'nginx' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);