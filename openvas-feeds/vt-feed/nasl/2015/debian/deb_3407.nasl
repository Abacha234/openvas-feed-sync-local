# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703407");
  script_cve_id("CVE-2015-0860");
  script_tag(name:"creation_date", value:"2015-11-25 23:00:00 +0000 (Wed, 25 Nov 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3407)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3407");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3407");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dpkg' package(s) announced via the DSA-3407 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Boeck discovered a stack-based buffer overflow in the dpkg-deb component of dpkg, the Debian package management system. This flaw could potentially lead to arbitrary code execution if a user or an automated system were tricked into processing a specially crafted Debian binary package (.deb) in the old style Debian binary package format.

This update also includes updated translations and additional bug fixes.

For the oldstable distribution (wheezy), this problem has been fixed in version 1.16.17.

For the stable distribution (jessie), this problem has been fixed in version 1.17.26.

We recommend that you upgrade your dpkg packages.");

  script_tag(name:"affected", value:"'dpkg' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);