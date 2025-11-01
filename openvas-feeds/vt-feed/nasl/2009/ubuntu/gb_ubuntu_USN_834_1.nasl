# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64982");
  script_cve_id("CVE-2007-6600", "CVE-2009-3229", "CVE-2009-3230", "CVE-2009-3231");
  script_tag(name:"creation_date", value:"2009-09-28 17:09:13 +0000 (Mon, 28 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-834-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-834-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-834-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-8.1, postgresql-8.3' package(s) announced via the USN-834-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PostgreSQL could be made to unload and reload an
already loaded module by using the LOAD command. A remote authenticated
attacker could exploit this to cause a denial of service. This issue did
not affect Ubuntu 6.06 LTS. (CVE-2009-3229)

Due to an incomplete fix for CVE-2007-6600, RESET ROLE and RESET SESSION
AUTHORIZATION operations were allowed inside security-definer functions. A
remote authenticated attacker could exploit this to escalate privileges
within PostgreSQL. (CVE-2009-3230)

It was discovered that PostgreSQL did not properly perform LDAP
authentication under certain circumstances. When configured to use LDAP
with anonymous binds, a remote attacker could bypass authentication by
supplying an empty password. This issue did not affect Ubuntu 6.06 LTS.
(CVE-2009-3231)");

  script_tag(name:"affected", value:"'postgresql-8.1, postgresql-8.3' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
