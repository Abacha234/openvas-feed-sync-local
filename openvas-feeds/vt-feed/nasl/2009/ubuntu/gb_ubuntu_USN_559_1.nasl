# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840106");
  script_cve_id("CVE-2007-3781", "CVE-2007-5925", "CVE-2007-5969", "CVE-2007-6304");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-559-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-559-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-559-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-dfsg-5.0' package(s) announced via the USN-559-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joe Gallo and Artem Russakovskii discovered that the InnoDB
engine in MySQL did not properly perform input validation. An
authenticated user could use a crafted CONTAINS statement to
cause a denial of service. (CVE-2007-5925)

It was discovered that under certain conditions MySQL could be
made to overwrite system table information. An authenticated
user could use a crafted RENAME statement to escalate privileges.
(CVE-2007-5969)

Philip Stoev discovered that the federated engine of MySQL
did not properly handle responses with a small number of columns.
An authenticated user could use a crafted response to a SHOW
TABLE STATUS query and cause a denial of service. (CVE-2007-6304)

It was discovered that MySQL did not properly enforce access
controls. An authenticated user could use a crafted CREATE TABLE
LIKE statement to escalate privileges. (CVE-2007-3781)");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
