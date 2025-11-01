# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702456");
  script_cve_id("CVE-2012-0920");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2456)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2456");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2456");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dropbear' package(s) announced via the DSA-2456 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Danny Fullerton discovered a use-after-free in the Dropbear SSH daemon, resulting in potential execution of arbitrary code. Exploitation is limited to users, who have been authenticated through public key authentication and for which command restrictions are in place.

For the stable distribution (squeeze), this problem has been fixed in version 0.52-5+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 2012.55-1.

For the unstable distribution (sid), this problem has been fixed in version 2012.55-1.

We recommend that you upgrade your dropbear packages.");

  script_tag(name:"affected", value:"'dropbear' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);