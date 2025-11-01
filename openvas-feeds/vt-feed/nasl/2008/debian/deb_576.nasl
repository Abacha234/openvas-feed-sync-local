# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53268");
  script_cve_id("CVE-1999-0710", "CVE-2004-0918");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-576)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-576");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-576");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squid' package(s) announced via the DSA-576 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in Squid, the internet object cache, the popular WWW proxy cache. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-1999-0710

It is possible to bypass access lists and scan arbitrary hosts and ports in the network through cachemgr.cgi, which is installed by default. This update disables this feature and introduces a configuration file (/etc/squid/cachemgr.conf) to control this behavior.

CAN-2004-0918

The asn_parse_header function (asn1.c) in the SNMP module for Squid allows remote attackers to cause a denial of service via certain SNMP packets with negative length fields that causes a memory allocation error.

For the stable distribution (woody) these problems have been fixed in version 2.4.6-2woody4.

For the unstable distribution (sid) these problems have been fixed in version 2.5.7-1.

We recommend that you upgrade your squid package.");

  script_tag(name:"affected", value:"'squid' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);