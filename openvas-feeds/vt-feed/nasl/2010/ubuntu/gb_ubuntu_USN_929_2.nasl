# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840424");
  script_cve_id("CVE-2010-1155", "CVE-2010-1156");
  script_tag(name:"creation_date", value:"2010-04-29 11:13:58 +0000 (Thu, 29 Apr 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-929-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-929-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-929-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/565182");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'irssi' package(s) announced via the USN-929-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-929-1 fixed vulnerabilities in irssi. The upstream changes introduced a
regression when using irssi with SSL and an IRC proxy. This update fixes
the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that irssi did not perform certificate host validation
 when using SSL connections. An attacker could exploit this to perform a man
 in the middle attack to view sensitive information or alter encrypted
 communications. (CVE-2010-1155)

 Aurelien Delaitre discovered that irssi could be made to dereference a NULL
 pointer when a user left the channel. A remote attacker could cause a
 denial of service via application crash. (CVE-2010-1156)

 This update also adds SSLv3 and TLSv1 support, while disabling the old,
 insecure SSLv2 protocol.");

  script_tag(name:"affected", value:"'irssi' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
