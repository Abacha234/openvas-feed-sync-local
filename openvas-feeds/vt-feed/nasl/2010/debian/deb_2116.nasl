# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68461");
  script_cve_id("CVE-2010-3311");
  script_tag(name:"creation_date", value:"2010-11-17 02:33:48 +0000 (Wed, 17 Nov 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2116)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2116");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2116");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freetype' package(s) announced via the DSA-2116 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marc Schoenefeld has found an input stream position error in the way the FreeType font rendering engine processed input file streams. If a user loaded a specially-crafted font file with an application linked against FreeType and relevant font glyphs were subsequently rendered with the X FreeType library (libXft), it could cause the application to crash or, possibly execute arbitrary code.

After the upgrade, all running applications and services that use libfreetype6 should be restarted. In most cases, logging out and in again should be enough. The script checkrestart from the debian-goodies package or lsof may help to find out which processes are still using the old version of libfreetype6.

For the stable distribution (lenny), these problems have been fixed in version 2.3.7-2+lenny4.

The testing distribution (squeeze) and the unstable distribution (sid) are not affected by this problem.

We recommend that you upgrade your freetype packages.");

  script_tag(name:"affected", value:"'freetype' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);