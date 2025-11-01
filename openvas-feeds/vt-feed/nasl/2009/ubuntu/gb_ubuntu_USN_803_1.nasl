# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64444");
  script_cve_id("CVE-2009-0692");
  script_tag(name:"creation_date", value:"2009-07-29 17:28:37 +0000 (Wed, 29 Jul 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-803-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-803-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-803-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcp3' package(s) announced via the USN-803-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the DHCP client as included in dhcp3 did not verify
the length of certain option fields when processing a response from an IPv4
dhcp server. If a user running Ubuntu 6.06 LTS or 8.04 LTS connected to a
malicious dhcp server, a remote attacker could cause a denial of service or
execute arbitrary code as the user invoking the program, typically the
'dhcp' user. For users running Ubuntu 8.10 or 9.04, a remote attacker
should only be able to cause a denial of service in the DHCP client. In
Ubuntu 9.04, attackers would also be isolated by the AppArmor dhclient3
profile.");

  script_tag(name:"affected", value:"'dhcp3' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
