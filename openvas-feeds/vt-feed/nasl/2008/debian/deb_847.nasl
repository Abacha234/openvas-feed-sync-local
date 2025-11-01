# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55562");
  script_cve_id("CVE-2005-2966");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-847)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-847");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-847");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dia' package(s) announced via the DSA-847 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joxean Koret discovered that the Python SVG import plugin in dia, a vector-oriented diagram editor, does not properly sanitise data read from an SVG file and is hence vulnerable to execute arbitrary Python code.

The old stable distribution (woody) is not affected by this problem.

For the stable distribution (sarge) this problem has been fixed in version 0.94.0-7sarge1.

For the unstable distribution (sid) this problem has been fixed in version 0.94.0-15.

We recommend that you upgrade your dia package.");

  script_tag(name:"affected", value:"'dia' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);