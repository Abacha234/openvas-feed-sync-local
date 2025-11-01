# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703901");
  script_cve_id("CVE-2017-7526");
  script_tag(name:"creation_date", value:"2017-07-01 22:00:00 +0000 (Sat, 01 Jul 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-3901)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3901");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3901");
  script_xref(name:"URL", value:"https://eprint.iacr.org/2017/627");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libgcrypt20' package(s) announced via the DSA-3901 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel J. Bernstein, Joachim Breitner, Daniel Genkin, Leon Groot Bruinderink, Nadia Heninger, Tanja Lange, Christine van Vredendaal and Yuval Yarom discovered that Libgcrypt is prone to a local side-channel attack allowing full key recovery for RSA-1024.

See [link moved to references] for details.

For the oldstable distribution (jessie), this problem has been fixed in version 1.6.3-2+deb8u4.

For the stable distribution (stretch), this problem has been fixed in version 1.7.6-2+deb9u1.

For the testing distribution (buster), this problem has been fixed in version 1.7.8-1.

For the unstable distribution (sid), this problem has been fixed in version 1.7.8-1.

We recommend that you upgrade your libgcrypt20 packages.");

  script_tag(name:"affected", value:"'libgcrypt20' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);