# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703269");
  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");
  script_tag(name:"creation_date", value:"2015-05-21 22:00:00 +0000 (Thu, 21 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-22 15:08:00 +0000 (Fri, 22 Nov 2019)");

  script_name("Debian: Security Advisory (DSA-3269)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3269");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3269");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-9.1' package(s) announced via the DSA-3269 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in PostgreSQL-9.1, a SQL database system.

CVE-2015-3165 (Remote crash)

SSL clients disconnecting just before the authentication timeout expires can cause the server to crash.

CVE-2015-3166 (Information exposure)

The replacement implementation of snprintf() failed to check for errors reported by the underlying system library calls, the main case that might be missed is out-of-memory situations. In the worst case this might lead to information exposure.

CVE-2015-3167 (Possible side-channel key exposure)

In contrib/pgcrypto, some cases of decryption with an incorrect key could report other error message texts. Fix by using a one-size-fits-all message.

For the oldstable distribution (wheezy), these problems have been fixed in version 9.1.16-0+deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 9.1.16-0+deb8u1. (Jessie contains a reduced postgresql-9.1 package, only CVE-2015-3166 is fixed in the produced binary package postgresql-plperl-9.1. We recommend to upgrade to postgresql-9.4 to get the full set of fixes. See the Jessie release notes for details.)

The testing distribution (stretch) and the unstable distribution (sid) do not contain the postgresql-9.1 package.

We recommend that you upgrade your postgresql-9.1 packages.");

  script_tag(name:"affected", value:"'postgresql-9.1' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);