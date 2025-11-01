# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66596");
  script_cve_id("CVE-2009-4022");
  script_tag(name:"creation_date", value:"2009-12-30 20:58:43 +0000 (Wed, 30 Dec 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1961)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1961");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1961");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-1961 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michael Sinatra discovered that the DNS resolver component in BIND does not properly check DNS records contained in additional sections of DNS responses, leading to a cache poisoning vulnerability. This vulnerability is only present in resolvers which have been configured with DNSSEC trust anchors, which is still rare.

Note that this update contains an internal ABI change, which means that all BIND-related packages (bind9, dnsutils and the library packages) must be updated at the same time (preferably using 'apt-get update' and 'apt-get upgrade'). In the unlikely event that you have compiled your own software against libdns, you must recompile this programs, too.

For the old stable distribution (etch), this problem has been fixed in version 9.3.4-2etch6.

For the stable distribution (lenny), this problem has been fixed in version 9.5.1.dfsg.P3-1+lenny1.

For the unstable distribution (sid) and the testing distribution (squeeze), this problem has been fixed in version 9.6.1.dfsg.P2-1.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);