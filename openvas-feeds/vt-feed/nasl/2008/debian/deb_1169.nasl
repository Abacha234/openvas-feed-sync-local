# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57337");
  script_cve_id("CVE-2006-4226", "CVE-2006-4380");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1169)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1169");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1169");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg-4.1' package(s) announced via the DSA-1169 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in the MySQL database server. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-4226

Michal Prokopiuk discovered that remote authenticated users are permitted to create and access a database if the lowercase spelling is the same as one they have been granted access to.

CVE-2006-4380

Beat Vontobel discovered that certain queries replicated to a slave could crash the client and thus terminate the replication.

For the stable distribution (sarge) these problems have been fixed in version 4.1.11a-4sarge7. Version 4.0 is not affected by these problems.

For the unstable distribution (sid) these problems have been fixed in version 5.0.24-3. The replication problem only exists in version 4.1.

We recommend that you upgrade your mysql-server-4.1 package.");

  script_tag(name:"affected", value:"'mysql-dfsg-4.1' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);