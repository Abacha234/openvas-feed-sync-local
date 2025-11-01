# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60359");
  script_cve_id("CVE-2007-5846");
  script_tag(name:"creation_date", value:"2008-02-15 22:29:21 +0000 (Fri, 15 Feb 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1483)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1483");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1483");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'net-snmp' package(s) announced via the DSA-1483 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SNMP agent (snmp_agent.c) in net-snmp before 5.4.1 allows remote attackers to cause a denial of service (CPU and memory consumption) via a GETBULK request with a large max-repeaters value.

For the stable distribution (etch), this problem has been fixed in version 5.2.3-7etch2.

For the unstable and testing distributions (sid and lenny, respectively), this problem has been fixed in version 5.4.1~dfsg-2.

We recommend that you upgrade your net-snmp package.");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);