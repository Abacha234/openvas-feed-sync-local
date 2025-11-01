# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840130");
  script_cve_id("CVE-2007-0555", "CVE-2007-0556");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-417-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-417-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-417-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-7.4, postgresql-8.0, postgresql-8.1' package(s) announced via the USN-417-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeff Trout discovered that the PostgreSQL server did not sufficiently
check data types of SQL function arguments in some cases. An
authenticated attacker could exploit this to crash the database server
or read out arbitrary locations in the server's memory, which could
allow retrieving database content the attacker should not be able to
see. (CVE-2007-0555)

Jeff Trout reported that the query planner did not verify that a table
was still compatible with a previously made query plan. By using ALTER
COLUMN TYPE during query execution, an attacker could exploit this to
read out arbitrary locations in the server's memory, which could allow
retrieving database content the attacker should not be able to see.
(CVE-2007-0556)");

  script_tag(name:"affected", value:"'postgresql-7.4, postgresql-8.0, postgresql-8.1' package(s) on Ubuntu 5.10, Ubuntu 6.06, Ubuntu 6.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
