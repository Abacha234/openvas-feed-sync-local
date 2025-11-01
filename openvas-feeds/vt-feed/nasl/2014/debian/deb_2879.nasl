# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702879");
  script_cve_id("CVE-2014-0017");
  script_tag(name:"creation_date", value:"2014-03-12 23:00:00 +0000 (Wed, 12 Mar 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2879)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2879");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2879");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libssh' package(s) announced via the DSA-2879 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libssh, a tiny C SSH library, did not reset the state of the PRNG after accepting a connection. A server mode application that forks itself to handle incoming connections could see its children sharing the same PRNG state, resulting in a cryptographic weakness and possibly the recovery of the private key.

For the oldstable distribution (squeeze), this problem has been fixed in version 0.4.5-3+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in version 0.5.4-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in version 0.5.4-3.

For the unstable distribution (sid), this problem has been fixed in version 0.5.4-3.

We recommend that you upgrade your libssh packages.");

  script_tag(name:"affected", value:"'libssh' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);