# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61853");
  script_cve_id("CVE-2008-0960", "CVE-2008-2292", "CVE-2008-4309");
  script_tag(name:"creation_date", value:"2008-11-19 15:52:57 +0000 (Wed, 19 Nov 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1663)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1663");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1663");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'net-snmp' package(s) announced via the DSA-1663 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in NET SNMP, a suite of Simple Network Management Protocol applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0960

Wes Hardaker reported that the SNMPv3 HMAC verification relies on the client to specify the HMAC length, which allows spoofing of authenticated SNMPv3 packets.

CVE-2008-2292

John Kortink reported a buffer overflow in the __snprint_value function in snmp_get causing a denial of service and potentially allowing the execution of arbitrary code via a large OCTETSTRING in an attribute value pair (AVP).

CVE-2008-4309

It was reported that an integer overflow in the netsnmp_create_subtree_cache function in agent/snmp_agent.c allows remote attackers to cause a denial of service attack via a crafted SNMP GETBULK request.

For the stable distribution (etch), these problems has been fixed in version 5.2.3-7etch4.

For the testing distribution (lenny) and unstable distribution (sid) these problems have been fixed in version 5.4.1~dfsg-11.

We recommend that you upgrade your net-snmp package.");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);