# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68460");
  script_cve_id("CVE-2010-3433");
  script_tag(name:"creation_date", value:"2010-11-17 02:33:48 +0000 (Wed, 17 Nov 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2120)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2120");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2120");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-8.3' package(s) announced via the DSA-2120 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tim Bunce discovered that PostgreSQL, a database server software, does not properly separate interpreters for server-side stored procedures which run in different security contexts. As a result, non-privileged authenticated database users might gain additional privileges.

Note that this security update may impact intended communication through global variables between stored procedures. It might be necessary to convert these functions to run under the plperlu or pltclu languages, with database superuser privileges.

This security update also includes unrelated bug fixes from PostgreSQL 8.3.12.

For the stable distribution (lenny), this problem has been fixed in version 8.3_8.3.12-0lenny1.

For the unstable distribution (sid), this problem has been fixed in version 8.4.5-1 of the postgresql-8.4 package.

We recommend that you upgrade your PostgreSQL packages.");

  script_tag(name:"affected", value:"'postgresql-8.3' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);