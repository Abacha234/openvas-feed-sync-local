# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840244");
  script_cve_id("CVE-2008-0960", "CVE-2008-2292", "CVE-2008-4309");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-685-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-685-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-685-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the USN-685-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wes Hardaker discovered that the SNMP service did not correctly validate
HMAC authentication requests. An unauthenticated remote attacker
could send specially crafted SNMPv3 traffic with a valid username
and gain access to the user's views without a valid authentication
passphrase. (CVE-2008-0960)

John Kortink discovered that the Net-SNMP Perl module did not correctly
check the size of returned values. If a user or automated system were
tricked into querying a malicious SNMP server, the application using
the Perl module could be made to crash, leading to a denial of service.
This did not affect Ubuntu 8.10. (CVE-2008-2292)

It was discovered that the SNMP service did not correctly handle large
GETBULK requests. If an unauthenticated remote attacker sent a specially
crafted request, the SNMP service could be made to crash, leading to a
denial of service. (CVE-2008-4309)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
