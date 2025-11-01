# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702730");
  script_cve_id("CVE-2013-4242");
  script_tag(name:"creation_date", value:"2013-07-28 22:00:00 +0000 (Sun, 28 Jul 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2730)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2730");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2730");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnupg' package(s) announced via the DSA-2730 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yarom and Falkner discovered that RSA secret keys could be leaked via a side channel attack, where a malicious local user could obtain private key information from another user on the system.

This update fixes this issue for the 1.4 series of GnuPG. GnuPG 2.x is affected through its use of the libgcrypt11 library, a fix for which will be published in DSA 2731.

For the oldstable distribution (squeeze), this problem has been fixed in version 1.4.10-4+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in version 1.4.12-7+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 1.4.14-1.

We recommend that you upgrade your gnupg packages.");

  script_tag(name:"affected", value:"'gnupg' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);