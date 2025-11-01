# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703621");
  script_cve_id("CVE-2015-2575");
  script_tag(name:"creation_date", value:"2016-07-17 22:00:00 +0000 (Sun, 17 Jul 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3621)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3621");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3621");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/connector-j/5.1/en/news-5-1.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html#AppendixMSQL");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-connector-java' package(s) announced via the DSA-3621 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in mysql-connector-java, a Java database (JDBC) driver for MySQL, which may result in unauthorized update, insert or delete access to some MySQL Connectors accessible data as well as read access to a subset of MySQL Connectors accessible data. The vulnerability was addressed by upgrading mysql-connector-java to the new upstream version 5.1.39, which includes additional changes, such as bug fixes, new features, and possibly incompatible changes. Please see the MySQL Connector/J Release Notes and Oracle's Critical Patch Update advisory for further details:

[link moved to references]

[link moved to references]

For the stable distribution (jessie), this problem has been fixed in version 5.1.39-1~deb8u1.

We recommend that you upgrade your mysql-connector-java packages.");

  script_tag(name:"affected", value:"'mysql-connector-java' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);