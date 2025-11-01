# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840921");
  script_cve_id("CVE-2012-0866", "CVE-2012-0867", "CVE-2012-0868");
  script_tag(name:"creation_date", value:"2012-03-07 05:50:04 +0000 (Wed, 07 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1378-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1378-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1378-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-8.3, postgresql-8.4, postgresql-9.1' package(s) announced via the USN-1378-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PostgreSQL incorrectly checked permissions on
functions called by a trigger. An attacker could attach a trigger to a
table they owned and possibly escalate privileges. (CVE-2012-0866)

It was discovered that PostgreSQL incorrectly truncated SSL certificate
name checks to 32 characters. If a host name was exactly 32 characters,
this issue could be exploited by an attacker to spoof the SSL certificate.
This issue affected Ubuntu 10.04 LTS, Ubuntu 10.10, Ubuntu 11.04 and
Ubuntu 11.10. (CVE-2012-0867)

It was discovered that the PostgreSQL pg_dump utility incorrectly filtered
line breaks in object names. An attacker could create object names that
execute arbitrary SQL commands when a dump script is reloaded.
(CVE-2012-0868)");

  script_tag(name:"affected", value:"'postgresql-8.3, postgresql-8.4, postgresql-9.1' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
