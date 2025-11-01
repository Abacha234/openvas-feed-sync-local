# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841785");
  script_cve_id("CVE-2014-0001", "CVE-2014-0384", "CVE-2014-2419", "CVE-2014-2430", "CVE-2014-2431", "CVE-2014-2432", "CVE-2014-2436", "CVE-2014-2438", "CVE-2014-2440");
  script_tag(name:"creation_date", value:"2014-05-02 04:40:53 +0000 (Fri, 02 May 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2170-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2170-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2170-1");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-36.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-37.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.5/en/default-privileges.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.5' package(s) announced via the USN-2170-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
a new upstream MySQL version to fix these issues. MySQL has been updated to
5.5.37.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]
[link moved to references]
[link moved to references]

Additionally, Matthias Reichl discovered that the mysql-5.5 packages were
missing the patches applied previously in the mysql-5.1 packages to drop
the default test database and localhost permissions granting access to any
databases starting with 'test_'. This update reintroduces these patches for
Ubuntu 12.04 LTS, Ubuntu 12.10, and Ubuntu 13.10. Existing test databases
and permissions will not be modified on upgrade. To manually restrict
access for existing installations, please refer to the following:

[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.5' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
