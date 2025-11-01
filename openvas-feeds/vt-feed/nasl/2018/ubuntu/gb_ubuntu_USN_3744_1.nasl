# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843619");
  script_cve_id("CVE-2018-10915", "CVE-2018-10925");
  script_tag(name:"creation_date", value:"2018-08-17 03:57:27 +0000 (Fri, 17 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-17 19:15:00 +0000 (Mon, 17 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3744-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3744-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3744-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-9.3, postgresql-9.5, postgresql-10' package(s) announced via the USN-3744-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrew Krasichkov discovered that the PostgreSQL client library incorrectly
reset its internal state between connections. A remote attacker could
possibly use this issue to bypass certain client-side connection security
features. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2018-10915)

It was discovered that PostgreSQL incorrectly checked authorization on
certain statements. A remote attacker could possibly use this issue to
read arbitrary server memory or alter certain data. (CVE-2018-10925)");

  script_tag(name:"affected", value:"'postgresql-9.3, postgresql-9.5, postgresql-10' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
