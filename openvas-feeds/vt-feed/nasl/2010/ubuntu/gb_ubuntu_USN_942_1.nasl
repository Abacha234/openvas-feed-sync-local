# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840434");
  script_cve_id("CVE-2010-1169", "CVE-2010-1170", "CVE-2010-1975");
  script_tag(name:"creation_date", value:"2010-05-28 08:00:59 +0000 (Fri, 28 May 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-942-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-942-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-942-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-8.1, postgresql-8.3, postgresql-8.4' package(s) announced via the USN-942-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Safe.pm module as used by PostgreSQL did not
properly restrict PL/perl procedures. If PostgreSQL was configured to use
Perl stored procedures, a remote authenticated attacker could exploit this
to execute arbitrary Perl code. (CVE-2010-1169)

It was discovered that PostgreSQL did not properly check permissions to
restrict PL/Tcl procedures. If PostgreSQL was configured to use Tcl stored
procedures, a remote authenticated attacker could exploit this to execute
arbitrary Tcl code. (CVE-2010-1170)

It was discovered that PostgreSQL did not properly check privileges during
certain RESET ALL operations. A remote authenticated attacker could exploit
this to remove all special parameter settings for a user or database.
(CVE-2010-1975)");

  script_tag(name:"affected", value:"'postgresql-8.1, postgresql-8.3, postgresql-8.4' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
