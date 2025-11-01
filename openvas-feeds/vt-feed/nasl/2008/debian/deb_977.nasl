# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56283");
  script_cve_id("CVE-2006-0582", "CVE-2006-0677");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-977)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-977");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-977");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'heimdal' package(s) announced via the DSA-977 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in heimdal, a free implementation of Kerberos 5. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2006-0582

Privilege escalation in the rsh server allows an authenticated attacker to overwrite arbitrary files and gain ownership of them.

CVE-2006-0677

A remote attacker could force the telnet server to crash before the user logged in, resulting in inetd turning telnetd off because it forked too fast.

The old stable distribution (woody) does not expose rsh and telnet servers.

For the stable distribution (sarge) these problems have been fixed in version 0.6.3-10sarge2.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your heimdal packages.");

  script_tag(name:"affected", value:"'heimdal' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);