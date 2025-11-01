# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70234");
  script_tag(name:"creation_date", value:"2011-09-21 03:47:11 +0000 (Wed, 21 Sep 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2299)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2299");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2299");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ca-certificates' package(s) announced via the DSA-2299 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An unauthorized SSL certificate has been found in the wild issued for the DigiNotar Certificate Authority, obtained through a security compromise with said company. Debian, like other software distributors, has as a precaution decided to disable the DigiNotar Root CA by default in its ca-certificates bundle.

For other software in Debian that ships a CA bundle, like the Mozilla suite, updates are forthcoming.

For the oldstable distribution (lenny), the ca-certificates package does not contain this root CA.

For the stable distribution (squeeze), the root CA has been disabled starting ca-certificates version 20090814+nmu3.

For the testing distribution (wheezy) and unstable distribution (sid), the root CA has been disabled starting ca-certificates version 20110502+nmu1.

We recommend that you upgrade your ca-certificates packages.");

  script_tag(name:"affected", value:"'ca-certificates' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);