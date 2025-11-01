# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56193");
  script_cve_id("CVE-2006-0045");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-949)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-949");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-949");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'crawl' package(s) announced via the DSA-949 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steve Kemp from the Debian Security Audit project discovered a security related problem in crawl, another console based dungeon exploration game in the vein of nethack and rogue. The program executes commands insecurely when saving or loading games which can allow local attackers to gain group games privileges.

For the old stable distribution (woody) this problem has been fixed in version 4.0.0beta23-2woody2.

For the stable distribution (sarge) this problem has been fixed in version 4.0.0beta26-4sarge0.

For the unstable distribution (sid) this problem has been fixed in version 4.0.0beta26-7.

We recommend that you upgrade your crawl package.");

  script_tag(name:"affected", value:"'crawl' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);