# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57109");
  script_cve_id("CVE-2006-3081", "CVE-2006-3469");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1112)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1112");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1112");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg-4.1' package(s) announced via the DSA-1112 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in the MySQL database server, which may lead to denial of service. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-3081

'Kanatoko' discovered that the server can be crashed with feeding NULL values to the str_to_date() function.

CVE-2006-3469

Jean-David Maillefer discovered that the server can be crashed with specially crafted date_format() function calls.

For the stable distribution (sarge) these problems have been fixed in version 4.1.11a-4sarge5.

For the unstable distribution (sid) does no longer contain MySQL 4.1 packages. MySQL 5.0 from sid is not affected.

We recommend that you upgrade your mysql-dfsg-4.1 packages.");

  script_tag(name:"affected", value:"'mysql-dfsg-4.1' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);