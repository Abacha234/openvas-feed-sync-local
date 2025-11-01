# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53671");
  script_cve_id("CVE-2003-0805");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-387)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-387");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-387");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gopher' package(s) announced via the DSA-387 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"gopherd, a gopher server from the University of Minnesota, contains a number of buffer overflows which could be exploited by a remote attacker to execute arbitrary code with the privileges of the gopherd process (the 'gopher' user by default).

For the stable distribution (woody) this problem has been fixed in version 3.0.3woody1.

This program has been removed from the unstable distribution (sid). gopherd is deprecated, and users are recommended to use PyGopherd instead.

We recommend that you update your gopherd package.");

  script_tag(name:"affected", value:"'gopher' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);