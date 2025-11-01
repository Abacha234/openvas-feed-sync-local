# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53108");
  script_cve_id("CVE-2003-0914");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-409)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-409");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-409");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind' package(s) announced via the DSA-409 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in BIND, a domain name server, whereby a malicious name server could return authoritative negative responses with a large TTL (time-to-live) value, thereby rendering a domain name unreachable. A successful attack would require that a vulnerable BIND instance submit a query to a malicious nameserver.

The bind9 package is not affected by this vulnerability.

For the current stable distribution (woody) this problem has been fixed in version 1:8.3.3-2.0woody2.

For the unstable distribution (sid) this problem has been fixed in version 1:8.4.3-1.

We recommend that you update your bind package.");

  script_tag(name:"affected", value:"'bind' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);