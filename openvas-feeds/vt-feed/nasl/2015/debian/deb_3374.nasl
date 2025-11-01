# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703374");
  script_cve_id("CVE-2015-5288", "CVE-2015-5289");
  script_tag(name:"creation_date", value:"2015-10-18 22:00:00 +0000 (Sun, 18 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3374)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3374");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3374");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-9.4' package(s) announced via the DSA-3374 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in PostgreSQL-9.4, a SQL database system.

CVE-2015-5288

Josh Kupershmidt discovered a vulnerability in the crypt() function in the pgCrypto extension. Certain invalid salt arguments can cause the server to crash or to disclose a few bytes of server memory.

CVE-2015-5289

Oskari Saarenmaa discovered that json or jsonb input values constructed from arbitrary user input can crash the PostgreSQL server and cause a denial of service.

For the stable distribution (jessie), these problems have been fixed in version 9.4.5-0+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 9.4.5-1.

For the unstable distribution (sid), these problems have been fixed in version 9.4.5-1.

We recommend that you upgrade your postgresql-9.4 packages.");

  script_tag(name:"affected", value:"'postgresql-9.4' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);