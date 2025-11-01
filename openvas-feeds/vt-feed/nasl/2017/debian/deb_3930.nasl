# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703930");
  script_cve_id("CVE-2017-10978", "CVE-2017-10983");
  script_tag(name:"creation_date", value:"2017-08-09 22:00:00 +0000 (Wed, 09 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3930)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3930");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3930");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freeradius' package(s) announced via the DSA-3930 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Guido Vranken discovered that FreeRADIUS, an open source implementation of RADIUS, the IETF protocol for AAA (Authorisation, Authentication, and Accounting), did not properly handle memory when processing packets. This would allow a remote attacker to cause a denial-of-service by application crash, or potentially execute arbitrary code.

All those issues are covered by this single DSA, but it's worth noting that not all issues affect all releases:

CVE-2017-10978 and CVE-2017-10983 affect both jessie and stretch,

CVE-2017-10979, CVE-2017-10980, CVE-2017-10981 and CVE-2017-10982 affect only jessie,

CVE-2017-10984, CVE-2017-10985, CVE-2017-10986 and CVE-2017-10987 affect only stretch.

For the oldstable distribution (jessie), these problems have been fixed in version 2.2.5+dfsg-0.2+deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 3.0.12+dfsg-5+deb9u1.

We recommend that you upgrade your freeradius packages.");

  script_tag(name:"affected", value:"'freeradius' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);