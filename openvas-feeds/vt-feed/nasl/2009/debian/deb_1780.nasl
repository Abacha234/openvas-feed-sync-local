# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63933");
  script_cve_id("CVE-2009-0663", "CVE-2009-1341");
  script_tag(name:"creation_date", value:"2009-05-05 14:00:35 +0000 (Tue, 05 May 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1780)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1780");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1780");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libdbd-pg-perl' package(s) announced via the DSA-1780 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in libdbd-pg-perl, the DBI driver module for PostgreSQL database access (DBD::Pg).

CVE-2009-0663

A heap-based buffer overflow may allow attackers to execute arbitrary code through applications which read rows from the database using the pg_getline and getline functions. (More common retrieval methods, such as selectall_arrayref and fetchrow_array, are not affected.)

CVE-2009-1341

A memory leak in the routine which unquotes BYTEA values returned from the database allows attackers to cause a denial of service.

For the old stable distribution (etch), these problems have been fixed in version 1.49-2+etch1.

For the stable distribution (lenny) and the unstable distribution (sid), these problems have been fixed in version 2.1.3-1 before the release of lenny.

We recommend that you upgrade your libdbd-pg-perl package.");

  script_tag(name:"affected", value:"'libdbd-pg-perl' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);