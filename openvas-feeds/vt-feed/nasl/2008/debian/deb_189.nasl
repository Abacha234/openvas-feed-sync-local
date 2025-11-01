# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53437");
  script_cve_id("CVE-2002-1245");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-189)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-189");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/dsa-189");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'luxman' package(s) announced via the DSA-189 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"iDEFENSE reported about a vulnerability in LuxMan, a maze game for GNU/Linux, similar to the PacMan arcade game. When successfully exploited a local attacker gains read-write access to the memory, leading to a local root compromise in many ways, examples of which include scanning the file for fragments of the master password file and modifying kernel memory to re-map system calls.

This problem has been fixed in version 0.41-17.1 for the current stable distribution (woody) and in version 0.41-19 for the unstable distribution (sid). The old stable distribution (potato) is not affected since it doesn't contain a luxman package.

We recommend that you upgrade your luxman package immediately.");

  script_tag(name:"affected", value:"'luxman' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);