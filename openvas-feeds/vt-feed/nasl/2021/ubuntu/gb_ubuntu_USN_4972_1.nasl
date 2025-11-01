# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844958");
  script_cve_id("CVE-2021-32027", "CVE-2021-32028", "CVE-2021-32029");
  script_tag(name:"creation_date", value:"2021-06-02 03:00:35 +0000 (Wed, 02 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-13 10:15:00 +0000 (Tue, 13 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4972-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4972-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4972-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-10, postgresql-12, postgresql-13' package(s) announced via the USN-4972-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tom Lane discovered that PostgreSQL incorrect handled certain array
subscripting calculations. An authenticated attacker could possibly use
this issue to overwrite server memory and escalate privileges.
(CVE-2021-32027)

Andres Freund discovered that PostgreSQL incorrect handled certain
INSERT ... ON CONFLICT ... DO UPDATE commands. A remote attacker could
possibly use this issue to read server memory and obtain sensitive
information. (CVE-2021-32028)

Tom Lane discovered that PostgreSQL incorrect handled certain UPDATE ...
RETURNING commands. A remote attacker could possibly use this issue to read
server memory and obtain sensitive information. This issue only affected
Ubuntu 20.04 LTS, Ubuntu 20.10, and Ubuntu 21.04. (CVE-2021-32029)");

  script_tag(name:"affected", value:"'postgresql-10, postgresql-12, postgresql-13' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
