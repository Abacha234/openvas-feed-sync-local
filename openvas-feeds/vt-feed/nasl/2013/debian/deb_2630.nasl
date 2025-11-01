# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702630");
  script_cve_id("CVE-2013-0255");
  script_tag(name:"creation_date", value:"2013-02-19 23:00:00 +0000 (Tue, 19 Feb 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2630)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2630");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2630");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-8.4' package(s) announced via the DSA-2630 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sumit Soni discovered that PostgreSQL, an object-relational SQL database, could be forced to crash when an internal function was called with invalid arguments, resulting in denial of service.

For the stable distribution (squeeze), this problem has been fixed in version 8.4.16-0squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 8.4.16-1.

For the unstable distribution (sid), this problem has been fixed in version 8.4.16-1.

We recommend that you upgrade your postgresql-8.4 packages.");

  script_tag(name:"affected", value:"'postgresql-8.4' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);