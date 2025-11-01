# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703706");
  script_cve_id("CVE-2016-5584", "CVE-2016-7440");
  script_tag(name:"creation_date", value:"2016-11-06 23:00:00 +0000 (Sun, 06 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-27 15:59:00 +0000 (Thu, 27 Oct 2022)");

  script_name("Debian: Security Advisory (DSA-3706)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3706");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3706");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-53.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-5.5' package(s) announced via the DSA-3706 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in the MySQL database server. The vulnerabilities are addressed by upgrading MySQL to the new upstream version 5.5.53, which includes additional changes, such as performance improvements, bug fixes, new features, and possibly incompatible changes. Please see the MySQL 5.5 Release Notes and Oracle's Critical Patch Update advisory for further details:

[link moved to references]

[link moved to references]

For the stable distribution (jessie), these problems have been fixed in version 5.5.53-0+deb8u1.

We recommend that you upgrade your mysql-5.5 packages.");

  script_tag(name:"affected", value:"'mysql-5.5' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);