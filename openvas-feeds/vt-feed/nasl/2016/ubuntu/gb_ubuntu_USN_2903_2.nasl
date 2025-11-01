# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842660");
  script_cve_id("CVE-2016-1938");
  script_tag(name:"creation_date", value:"2016-02-24 05:25:30 +0000 (Wed, 24 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2903-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2903-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2903-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1547147");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss' package(s) announced via the USN-2903-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2903-1 fixed a vulnerability in NSS. An incorrect package versioning
change in Ubuntu 12.04 LTS caused a regression when building software
against NSS. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Hanno Bock discovered that NSS incorrectly handled certain division
 functions, possibly leading to cryptographic weaknesses. (CVE-2016-1938)

 This update also refreshes the NSS package to version 3.21 which includes
 the latest CA certificate bundle, and removes the SPI CA.");

  script_tag(name:"affected", value:"'nss' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
