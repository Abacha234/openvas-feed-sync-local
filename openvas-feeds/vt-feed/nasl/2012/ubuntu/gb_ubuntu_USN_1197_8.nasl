# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840971");
  script_tag(name:"creation_date", value:"2012-04-02 05:05:00 +0000 (Mon, 02 Apr 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1197-8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1197-8");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1197-8");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/967961");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ca-certificates-java' package(s) announced via the USN-1197-8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1197-7 fixed a vulnerability in ca-certificates-java. The new package
broke upgrades from Ubuntu 11.04 to Ubuntu 11.10. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Dutch Certificate Authority DigiNotar had
 mis-issued multiple fraudulent certificates. These certificates could allow
 an attacker to perform a 'machine-in-the-middle' (MITM) attack which would make
 the user believe their connection is secure, but is actually being
 monitored.");

  script_tag(name:"affected", value:"'ca-certificates-java' package(s) on Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
