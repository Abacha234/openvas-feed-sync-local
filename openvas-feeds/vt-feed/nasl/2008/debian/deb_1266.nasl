# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58121");
  script_cve_id("CVE-2007-1263");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1266)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1266");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1266");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnupg' package(s) announced via the DSA-1266 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gerardo Richarte discovered that GnuPG, a free PGP replacement, provides insufficient user feedback if an OpenPGP message contains both unsigned and signed portions. Inserting text segments into an otherwise signed message could be exploited to forge the content of signed messages. This update prevents such attacks, the old behaviour can still be activated by passing the --allow-multiple-messages option.

For the stable distribution (sarge) these problems have been fixed in version 1.4.1-1.sarge7.

For the upcoming stable distribution (etch) these problems have been fixed in version 1.4.6-2.

For the unstable distribution (sid) these problems have been fixed in version 1.4.6-2.

We recommend that you upgrade your gnupg packages.");

  script_tag(name:"affected", value:"'gnupg' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);