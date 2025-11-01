# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65005");
  script_cve_id("CVE-2009-3229", "CVE-2009-3230", "CVE-2009-3231");
  script_tag(name:"creation_date", value:"2009-10-06 00:49:40 +0000 (Tue, 06 Oct 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1900)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1900");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1900");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-7.4, postgresql-8.1, postgresql-8.3' package(s) announced via the DSA-1900 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in PostgreSQL, an SQL database system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-3229

Authenticated users can shut down the backend server by re-LOAD-ing libraries in $libdir/plugins, if any libraries are present there. (The old stable distribution (etch) is not affected by this issue.)

CVE-2009-3230

Authenticated non-superusers can gain database superuser privileges if they can create functions and tables due to incorrect execution of functions in functional indexes.

CVE-2009-3231

If PostgreSQL is configured with LDAP authentication, and the LDAP configuration allows anonymous binds, it is possible for a user to authenticate themselves with an empty password. (The old stable distribution (etch) is not affected by this issue.)

In addition, this update contains reliability improvements which do not target security issues.

For the old stable distribution (etch), these problems have been fixed in version 7.4.26-0etch1 of the postgresql-7.4 source package, and version 8.1.18-0etch1 of the postgresql-8.1 source package.

For the stable distribution (lenny), these problems have been fixed in version 8.3.8-0lenny1 of the postgresql-8.3 source package.

For the unstable distribution (sid), these problems have been fixed in version 8.3.8-1 of the postgresql-8.3 source package, and version 8.4.1-1 of the postgresql-8.4 source package.

We recommend that you upgrade your PostgreSQL packages.");

  script_tag(name:"affected", value:"'postgresql-7.4, postgresql-8.1, postgresql-8.3' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);