# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841727");
  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066");
  script_tag(name:"creation_date", value:"2014-02-25 11:23:04 +0000 (Tue, 25 Feb 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2120-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2120-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2120-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-8.4, postgresql-9.1' package(s) announced via the USN-2120-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Noah Misch and Jonas Sundman discovered that PostgreSQL did not correctly
enforce ADMIN OPTION restrictions. An authenticated attacker could use this
issue to possibly revoke access from others, contrary to expected
permissions. (CVE-2014-0060)

Andres Freund discovered that PostgreSQL incorrectly handled validator
functions. An authenticated attacker could possibly use this issue to
escalate their privileges. (CVE-2014-0061)

Andres Freund discovered that PostgreSQL incorrectly handled concurrent
CREATE INDEX statements. An authenticated attacker could possibly use this
issue to obtain access to restricted data, bypassing intended privileges.
(CVE-2014-0062)

Daniel Schussler discovered that PostgreSQL incorrectly handled datetime
input. An authenticated attacker could possibly use this issue to cause
PostgreSQL to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2014-0063)

It was discovered that PostgreSQL incorrectly handled certain size
calculations. An authenticated attacker could possibly use this issue to
cause PostgreSQL to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2014-0064)

Peter Eisentraut and Jozef Mlich discovered that PostgreSQL incorrectly
handled certain buffer sizes. An authenticated attacker could possibly use
this issue to cause PostgreSQL to crash, resulting in a denial of service,
or possibly execute arbitrary code. (CVE-2014-0065)

Honza Horak discovered that PostgreSQL incorrectly used the crypt() library
function. This issue could possibly cause PostgreSQL to crash, resulting in
a denial of service (CVE-2014-0066)");

  script_tag(name:"affected", value:"'postgresql-8.4, postgresql-9.1' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
