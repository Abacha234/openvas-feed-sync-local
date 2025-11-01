# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61357");
  script_cve_id("CVE-2008-0983");
  script_tag(name:"creation_date", value:"2008-08-15 13:52:52 +0000 (Fri, 15 Aug 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1609)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1609");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1609");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lighttpd' package(s) announced via the DSA-1609 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local/remote vulnerabilities have been discovered in lighttpd, a fast webserver with minimal memory footprint.

The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0983

lighttpd 1.4.18, and possibly other versions before 1.5.0, does not properly calculate the size of a file descriptor array, which allows remote attackers to cause a denial of service (crash) via a large number of connections, which triggers an out-of-bounds access.

CVE-2007-3948

connections.c in lighttpd before 1.4.16 might accept more connections than the configured maximum, which allows remote attackers to cause a denial of service (failed assertion) via a large number of connection attempts.

For the stable distribution (etch), these problems have been fixed in version 1.4.13-4etch9.

For the unstable distribution (sid), these problems have been fixed in version 1.4.18-2.

We recommend that you upgrade your lighttpd package.");

  script_tag(name:"affected", value:"'lighttpd' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);