# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64419");
  script_cve_id("CVE-2009-0858");
  script_tag(name:"creation_date", value:"2009-07-29 17:28:37 +0000 (Wed, 29 Jul 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1831)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1831");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1831");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'djbdns' package(s) announced via the DSA-1831 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matthew Dempsky discovered that Daniel J. Bernstein's djbdns, a Domain Name System server, does not constrain offsets in the required manner, which allows remote attackers with control over a third-party subdomain served by tinydns and axfrdns, to trigger DNS responses containing arbitrary records via crafted zone data for this subdomain.

The old stable distribution (etch) does not contain djbdns.

For the stable distribution (lenny), this problem has been fixed in version 1.05-4+lenny1.

For the unstable distribution (sid), this problem has been fixed in version 1.05-5.

We recommend that you upgrade your djbdns package.");

  script_tag(name:"affected", value:"'djbdns' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);