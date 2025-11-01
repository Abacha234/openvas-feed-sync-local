# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61711");
  script_cve_id("CVE-2008-4440");
  script_tag(name:"creation_date", value:"2008-10-08 22:42:36 +0000 (Wed, 08 Oct 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1643)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1643");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1643");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'feta' package(s) announced via the DSA-1643 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dmitry E. Oboukhov discovered that the 'to-upgrade' plugin of Feta, a simpler interface to APT, dpkg, and other Debian package tools creates temporary files insecurely, which may lead to local denial of service through symlink attacks.

For the stable distribution (etch), this problem has been fixed in version 1.4.15+etch1.

For the unstable distribution (sid), this problem has been fixed in version 1.4.16+nmu1.

We recommend that you upgrade your feta package.");

  script_tag(name:"affected", value:"'feta' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);