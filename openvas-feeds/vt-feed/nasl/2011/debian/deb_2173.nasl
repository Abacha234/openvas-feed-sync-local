# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69107");
  script_tag(name:"creation_date", value:"2011-03-09 04:54:11 +0000 (Wed, 09 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2173)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2173");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2173");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pam-pgsql' package(s) announced via the DSA-2173 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that pam-pgsql, a PAM module to authenticate using a PostgreSQL database, was vulnerable to a buffer overflow in supplied IP-addresses.

For the oldstable distribution (lenny), this problem has been fixed in version 0.6.3-2+lenny1.

For the stable distribution (squeeze), this problem has been fixed in version 0.7.1-4+squeeze1.

For the testing (wheezy) and unstable (sid) distributions, this problem has been fixed in version 0.7.1-5.

We recommend that you upgrade your pam-pgsql packages.");

  script_tag(name:"affected", value:"'pam-pgsql' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);