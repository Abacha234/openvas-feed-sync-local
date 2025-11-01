# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840417");
  script_tag(name:"creation_date", value:"2010-04-16 15:02:11 +0000 (Fri, 16 Apr 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-927-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-927-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-927-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/559918");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-927-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-927-1 fixed vulnerabilities in NSS. Due to upstream changes in NSS
3.12.6, Thunderbird would be unable to initialize the security component
and connect with SSL/TLS if the old libnss3-0d transition package was
installed. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Marsh Ray and Steve Dispensa discovered a flaw in the TLS and SSLv3
 protocols. If an attacker could perform a machine-in-the-middle attack at the
 start of a TLS connection, the attacker could inject arbitrary content at
 the beginning of the user's session. This update adds support for the new
 new renegotiation extension and will use it when the server supports it.");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
