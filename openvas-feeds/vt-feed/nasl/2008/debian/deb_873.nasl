# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55748");
  script_cve_id("CVE-2005-2177");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-873)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-873");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-873");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'net-snmp' package(s) announced via the DSA-873 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A security vulnerability has been found in Net-SNMP releases that could allow a denial of service attack against Net-SNMP agents that have opened a stream based protocol (e.g. TCP but not UDP). By default, Net-SNMP does not open a TCP port.

The old stable distribution (woody) does not contain a net-snmp package.

For the stable distribution (sarge) this problem has been fixed in version 5.1.2-6.2.

For the unstable distribution (sid) this problem has been fixed in version 5.2.1.2-1.

We recommend that you upgrade your net-snmp package.");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);