# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61360");
  script_cve_id("CVE-2008-1637", "CVE-2008-3217");
  script_tag(name:"creation_date", value:"2008-08-15 13:52:52 +0000 (Fri, 15 Aug 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1544)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1544");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1544");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pdns-recursor' package(s) announced via the DSA-1544 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Amit Klein discovered that pdns-recursor, a caching DNS resolver, uses a weak random number generator to create DNS transaction IDs and UDP source port numbers. As a result, cache poisoning attacks were simplified. (CVE-2008-1637 and CVE-2008-3217)

For the stable distribution (etch), these problems have been fixed in version 3.1.4-1+etch2.

For the unstable distribution (sid), these problems have been fixed in version 3.1.7-1.

We recommend that you upgrade your pdns-recursor package.");

  script_tag(name:"affected", value:"'pdns-recursor' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);