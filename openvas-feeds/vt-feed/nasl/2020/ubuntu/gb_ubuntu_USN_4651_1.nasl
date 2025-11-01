# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844738");
  script_tag(name:"creation_date", value:"2020-12-01 04:00:53 +0000 (Tue, 01 Dec 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4651-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4651-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4651-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1857584");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-8.0' package(s) announced via the USN-4651-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tom Reynolds discovered that due to a packaging error, the MySQL X Plugin
was listening to all network interfaces by default, contrary to
expectations.

This update changes the default MySQL configuration to bind the MySQL X
Plugin to localhost only. This change may impact environments where the
MySQL X Plugin needs to be accessible from the network. The
mysqlx-bind-address setting in the /etc/mysql/mysql.conf.d/mysqld.cnf file
can be modified to allow network access.");

  script_tag(name:"affected", value:"'mysql-8.0' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
