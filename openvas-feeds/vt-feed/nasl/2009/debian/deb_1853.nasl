# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64630");
  script_cve_id("CVE-2009-2415");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1853)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1853");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1853");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'memcached' package(s) announced via the DSA-1853 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ronald Volgers discovered that memcached, a high-performance memory object caching system, is vulnerable to several heap-based buffer overflows due to integer conversions when parsing certain length attributes. An attacker can use this to execute arbitrary code on the system running memcached (on etch with root privileges).

For the oldstable distribution (etch), this problem has been fixed in version 1.1.12-1+etch1.

For the stable distribution (lenny), this problem has been fixed in version 1.2.2-1+lenny1.

For the testing (squeeze) and unstable (sid) distribution, this problem will be fixed soon.

We recommend that you upgrade your memcached packages.");

  script_tag(name:"affected", value:"'memcached' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);