# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891874");
  script_cve_id("CVE-2019-10208");
  script_tag(name:"creation_date", value:"2019-08-10 02:00:07 +0000 (Sat, 10 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-17 19:15:00 +0000 (Mon, 17 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-1874)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1874");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1874");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/devel/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-9.4' package(s) announced via the DLA-1874 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* CVE-2019-10208: `TYPE` in `pg_temp` executes arbitrary SQL during `SECURITY DEFINER` execution

Versions Affected: 9.4 - 11

Given a suitable `SECURITY DEFINER` function, an attacker can execute arbitrary SQL under the identity of the function owner. An attack requires `EXECUTE` permission on the function, which must itself contain a function call having inexact argument type match. For example, `length('foo'::varchar)` and `length('foo')` are inexact, while `length('foo'::text)` is exact. As part of exploiting this vulnerability, the attacker uses `CREATE DOMAIN` to create a type in a `pg_temp` schema. The attack pattern and fix are similar to that for CVE-2007-2138.

Writing `SECURITY DEFINER` functions continues to require following the considerations noted in the documentation:

[link moved to references]

The PostgreSQL project thanks Tom Lane for reporting this problem.

For Debian 8 Jessie, this problem has been fixed in version 9.4.24-0+deb8u1.

We recommend that you upgrade your postgresql-9.4 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'postgresql-9.4' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);