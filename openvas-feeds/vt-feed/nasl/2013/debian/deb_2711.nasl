# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702711");
  script_cve_id("CVE-2012-2942", "CVE-2013-1912", "CVE-2013-2175");
  script_tag(name:"creation_date", value:"2013-06-18 22:00:00 +0000 (Tue, 18 Jun 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2711)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2711");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2711");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'haproxy' package(s) announced via the DSA-2711 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in HAProxy, a load-balancing reverse proxy:

CVE-2012-2942

Buffer overflow in the header capture code.

CVE-2013-1912

Buffer overflow in the HTTP keepalive code.

CVE-2013-2175

Denial of service in parsing HTTP headers.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.4.8-1+squeeze1.

The stable distribution (wheezy) doesn't contain haproxy.

For the unstable distribution (sid), these problems have been fixed in version 1.4.24-1.

We recommend that you upgrade your haproxy packages.");

  script_tag(name:"affected", value:"'haproxy' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);