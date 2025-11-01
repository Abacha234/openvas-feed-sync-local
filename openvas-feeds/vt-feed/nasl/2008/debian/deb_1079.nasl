# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56833");
  script_cve_id("CVE-2006-0903", "CVE-2006-1516", "CVE-2006-1517", "CVE-2006-1518");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1079)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1079");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1079");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg' package(s) announced via the DSA-1079 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in MySQL, a popular SQL database. The Common Vulnerabilities and Exposures Project identifies the following problems:

CVE-2006-0903

Improper handling of SQL queries containing the NULL character allows local users to bypass logging mechanisms.

CVE-2006-1516

Usernames without a trailing null byte allow remote attackers to read portions of memory.

CVE-2006-1517

A request with an incorrect packet length allows remote attackers to obtain sensitive information.

CVE-2006-1518

Specially crafted request packets with invalid length values allow the execution of arbitrary code.

The following vulnerability matrix shows which version of MySQL in which distribution has this problem fixed:



woody

sarge

sid

mysql

3.23.49-8.15

n/a

n/a

mysql-dfsg

n/a

4.0.24-10sarge2

n/a

mysql-dfsg-4.1

n/a

4.1.11a-4sarge3

n/a

mysql-dfsg-5.0

n/a

n/a

5.0.21-3

We recommend that you upgrade your mysql packages.");

  script_tag(name:"affected", value:"'mysql-dfsg' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);