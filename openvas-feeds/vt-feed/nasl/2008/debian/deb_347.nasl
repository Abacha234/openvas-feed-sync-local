# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53636");
  script_cve_id("CVE-2003-0515");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-347)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-347");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-347");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'teapop' package(s) announced via the DSA-347 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"teapop, a POP-3 server, includes modules for authenticating users against a PostgreSQL or MySQL database. These modules do not properly escape user-supplied strings before using them in SQL queries. This vulnerability could be exploited to execute arbitrary SQL code under the privileges of the database user as which teapop has authenticated.

For the stable distribution (woody) this problem has been fixed in version 0.3.4-1woody2.

For the unstable distribution (sid) this problem has been fixed in version 0.3.5-2.

We recommend that you update your teapop package.");

  script_tag(name:"affected", value:"'teapop' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);