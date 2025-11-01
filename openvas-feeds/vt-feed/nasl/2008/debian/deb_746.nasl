# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54354");
  script_cve_id("CVE-2005-1921");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-746)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-746");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-746");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpgroupware' package(s) announced via the DSA-746 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability had been identified in the xmlrpc library included with phpgroupware, a web-based application including email, calendar and other groupware functionality. This vulnerability could lead to the execution of arbitrary commands on the server running phpgroupware.

The security team is continuing to investigate the version of phpgroupware included with the old stable distribution (woody). At this time we recommend disabling phpgroupware or upgrading to the current stable distribution (sarge).

For the current stable distribution (sarge) this problem has been fixed in version 0.9.16.005-3.sarge0.

For the unstable distribution (sid) this problem has been fixed in version 0.9.16.006-1.

We recommend that you upgrade your phpgroupware package.");

  script_tag(name:"affected", value:"'phpgroupware' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);