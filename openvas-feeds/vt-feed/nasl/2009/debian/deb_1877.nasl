# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64820");
  script_cve_id("CVE-2009-2446");
  script_tag(name:"creation_date", value:"2009-09-09 00:15:49 +0000 (Wed, 09 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1877)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1877");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1877");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg-5.0' package(s) announced via the DSA-1877 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In MySQL 4.0.0 through 5.0.83, multiple format string vulnerabilities in the dispatch_command() function in libmysqld/sql_parse.cc in mysqld allow remote authenticated users to cause a denial of service (daemon crash) and potentially the execution of arbitrary code via format string specifiers in a database name in a COM_CREATE_DB or COM_DROP_DB request.

For the stable distribution (lenny), this problem has been fixed in version 5.0.51a-24+lenny2.

For the old stable distribution (etch), this problem has been fixed in version 5.0.32-7etch11.

We recommend that you upgrade your mysql packages.");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);