# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63272");
  script_cve_id("CVE-2008-5394");
  script_tag(name:"creation_date", value:"2009-01-26 17:18:20 +0000 (Mon, 26 Jan 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1709)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1709");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1709");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'shadow' package(s) announced via the DSA-1709 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul Szabo discovered that login, the system login tool, did not correctly handle symlinks while setting up tty permissions. If a local attacker were able to gain control of the system utmp file, they could cause login to change the ownership and permissions on arbitrary files, leading to a root privilege escalation.

For the stable distribution (etch), this problem has been fixed in version 4.0.18.1-7+etch1.

For the unstable distribution (sid), this problem has been fixed in version 4.1.1-6.

We recommend that you upgrade your shadow package.");

  script_tag(name:"affected", value:"'shadow' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);