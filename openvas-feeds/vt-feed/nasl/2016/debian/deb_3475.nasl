# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703475");
  script_cve_id("CVE-2015-5288", "CVE-2016-0766", "CVE-2016-0773");
  script_tag(name:"creation_date", value:"2016-02-12 23:00:00 +0000 (Fri, 12 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 20:09:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Debian: Security Advisory (DSA-3475)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3475");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3475");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-9.1' package(s) announced via the DSA-3475 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in PostgreSQL-9.1, a SQL database system.

CVE-2015-5288

Josh Kupershmidt discovered a vulnerability in the crypt() function in the pgCrypto extension. Certain invalid salt arguments can cause the server to crash or to disclose a few bytes of server memory.

CVE-2016-0766

A privilege escalation vulnerability for users of PL/Java was discovered. Certain custom configuration settings (GUCs) for PL/Java will now be modifiable only by the database superuser to mitigate this issue.

CVE-2016-0773

Tom Lane and Greg Stark discovered a flaw in the way PostgreSQL processes specially crafted regular expressions. Very large character ranges in bracket expressions could cause infinite loops or memory overwrites. A remote attacker can exploit this flaw to cause a denial of service or, potentially, to execute arbitrary code.

For the oldstable distribution (wheezy), these problems have been fixed in version 9.1.20-0+deb7u1.

We recommend that you upgrade your postgresql-9.1 packages.");

  script_tag(name:"affected", value:"'postgresql-9.1' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);