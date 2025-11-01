# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702703");
  script_cve_id("CVE-2013-1968", "CVE-2013-2112");
  script_tag(name:"creation_date", value:"2013-06-08 22:00:00 +0000 (Sat, 08 Jun 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2703)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2703");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2703");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'subversion' package(s) announced via the DSA-2703 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Subversion, a version control system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-1968

Subversion repositories with the FSFS repository data store format can be corrupted by newline characters in filenames. A remote attacker with a malicious client could use this flaw to disrupt the service for other users using that repository.

CVE-2013-2112

Subversion's svnserve server process may exit when an incoming TCP connection is closed early in the connection process. A remote attacker can cause svnserve to exit and thus deny service to users of the server.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.6.12dfsg-7.

For the stable distribution (wheezy), these problems have been fixed in version 1.6.17dfsg-4+deb7u3.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your subversion packages.");

  script_tag(name:"affected", value:"'subversion' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);