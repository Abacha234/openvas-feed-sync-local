# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843073");
  script_tag(name:"creation_date", value:"2017-03-04 04:49:36 +0000 (Sat, 04 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3215-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3215-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3215-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1669764");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'munin' package(s) announced via the USN-3215-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3215-1 fixed a vulnerability in Munin. The upstream patch caused a
regression leading to errors being appended to the log file. This update
fixes the problem.

Original advisory details:

 It was discovered that Munin incorrectly handled CGI graphs. A remote
 attacker could use this issue to overwrite arbitrary files as the www-data
 user.");

  script_tag(name:"affected", value:"'munin' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
