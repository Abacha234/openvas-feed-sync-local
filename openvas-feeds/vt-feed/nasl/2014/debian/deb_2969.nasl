# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702969");
  script_cve_id("CVE-2014-0477", "CVE-2014-4720");
  script_tag(name:"creation_date", value:"2014-06-26 22:00:00 +0000 (Thu, 26 Jun 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2969)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2969");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2969");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libemail-address-perl' package(s) announced via the DSA-2969 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bastian Blank reported a denial of service vulnerability in Email::Address, a Perl module for RFC 2822 address parsing and creation. Email::Address::parse used significant time on parsing empty quoted strings. A remote attacker able to supply specifically crafted input to an application using Email::Address for parsing, could use this flaw to mount a denial of service attack against the application.

For the stable distribution (wheezy), this problem has been fixed in version 1.895-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in version 1.905-1.

For the unstable distribution (sid), this problem has been fixed in version 1.905-1.

We recommend that you upgrade your libemail-address-perl packages.");

  script_tag(name:"affected", value:"'libemail-address-perl' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);