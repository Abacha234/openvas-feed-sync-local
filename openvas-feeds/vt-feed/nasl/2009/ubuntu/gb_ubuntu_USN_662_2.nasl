# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840257");
  script_cve_id("CVE-2008-4395");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-662-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-662-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-662-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ubuntu-modules-2.6.22, linux-ubuntu-modules-2.6.24' package(s) announced via the USN-662-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-662-1 fixed vulnerabilities in ndiswrapper in Ubuntu 8.10.
This update provides the corresponding updates for Ubuntu 8.04 and 7.10.

Original advisory details:

 Anders Kaseorg discovered that ndiswrapper did not correctly handle long
 ESSIDs. For a system using ndiswrapper, a physically near-by attacker
 could generate specially crafted wireless network traffic and execute
 arbitrary code with root privileges. (CVE-2008-4395)");

  script_tag(name:"affected", value:"'linux-ubuntu-modules-2.6.22, linux-ubuntu-modules-2.6.24' package(s) on Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
