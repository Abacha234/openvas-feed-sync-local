# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841039");
  script_cve_id("CVE-2012-2122");
  script_tag(name:"creation_date", value:"2012-06-15 04:16:52 +0000 (Fri, 15 Jun 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1467-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1467-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1467-1");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-24.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-63.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.1, mysql-5.5, mysql-dfsg-5.0, mysql-dfsg-5.1' package(s) announced via the USN-1467-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that certain builds of MySQL incorrectly handled password
authentication on certain platforms. A remote attacker could use this issue
to authenticate with an arbitrary password and establish a connection.
(CVE-2012-2122)

MySQL has been updated to 5.5.24 in Ubuntu 12.04 LTS. Ubuntu 10.04 LTS,
Ubuntu 11.04 and Ubuntu 11.10 have been updated to MySQL 5.1.63. A patch to
fix the issue was backported to the version of MySQL in Ubuntu 8.04 LTS.

In addition to additional security fixes, the updated packages contain bug
fixes, new features, and possibly incompatible changes.

Please see the following for more information:

[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.1, mysql-5.5, mysql-dfsg-5.0, mysql-dfsg-5.1' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
