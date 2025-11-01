# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69568");
  script_cve_id("CVE-2011-1147", "CVE-2011-1174", "CVE-2011-1175", "CVE-2011-1507", "CVE-2011-1599");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2225)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2225");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2225");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DSA-2225 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Asterisk, an Open Source PBX and telephony toolkit.

CVE-2011-1147

Matthew Nicholson discovered that incorrect handling of UDPTL packets may lead to denial of service or the execution of arbitrary code.

CVE-2011-1174

Blake Cornell discovered that incorrect connection handling in the manager interface may lead to denial of service.

CVE-2011-1175

Blake Cornell and Chris May discovered that incorrect TCP connection handling may lead to denial of service.

CVE-2011-1507

Tzafrir Cohen discovered that insufficient limitation of connection requests in several TCP based services may lead to denial of service. Please see AST-2011-005 for details.

CVE-2011-1599

Matthew Nicholson discovered a privilege escalation vulnerability in the manager interface.

For the oldstable distribution (lenny), this problem has been fixed in version 1:1.4.21.2~dfsg-3+lenny2.1.

For the stable distribution (squeeze), this problem has been fixed in version 1:1.6.2.9-2+squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 1:1.8.3.3-1.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);