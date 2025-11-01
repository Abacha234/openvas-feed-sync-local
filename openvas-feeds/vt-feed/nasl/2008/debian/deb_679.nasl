# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53508");
  script_cve_id("CVE-2005-0159");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-679)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-679");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-679");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'toolchain-source' package(s) announced via the DSA-679 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sean Finney discovered several insecure temporary file uses in toolchain-source, the GNU binutils and GCC source code and scripts. These bugs can lead a local attacker with minimal knowledge to trick the admin into overwriting arbitrary files via a symlink attack. The problems exist inside the Debian-specific tpkg-* scripts.

For the stable distribution (woody) these problems have been fixed in version 3.0.4-1woody1.

For the unstable distribution (sid) these problems have been fixed in version 3.4-5.

We recommend that you upgrade your toolchain-source package.");

  script_tag(name:"affected", value:"'toolchain-source' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);