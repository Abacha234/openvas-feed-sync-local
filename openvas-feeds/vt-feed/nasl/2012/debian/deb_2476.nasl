# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71354");
  script_cve_id("CVE-2012-2369");
  script_tag(name:"creation_date", value:"2012-05-31 15:51:37 +0000 (Thu, 31 May 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2476)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2476");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2476");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pidgin-otr' package(s) announced via the DSA-2476 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"intrigeri discovered a format string error in pidgin-otr, an Off-the-Record Messaging plugin for Pidgin.

This could be exploited by a remote attacker to cause arbitrary code to be executed on the user's machine.

The problem is only in pidgin-otr. Other applications which use libotr are not affected.

For the stable distribution (squeeze), this problem has been fixed in version 3.2.0-5+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 3.2.1-1.

For the unstable distribution (sid), this problem has been fixed in version 3.2.1-1.

We recommend that you upgrade your pidgin-otr packages.");

  script_tag(name:"affected", value:"'pidgin-otr' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);