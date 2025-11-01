# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58734");
  script_cve_id("CVE-2007-3921");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1402)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1402");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1402");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gforge' package(s) announced via the DSA-1402 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steve Kemp from the Debian Security Audit project discovered that gforge, a collaborative development tool, used temporary files insecurely which could allow local users to truncate files upon the system with the privileges of the gforge user, or create a denial of service attack.

For the old stable distribution (sarge), this problem has been fixed in version 3.1-31sarge4.

For the stable distribution (etch), this problem has been fixed in version 4.5.14-22etch3.

We recommend that you upgrade your gforge package.");

  script_tag(name:"affected", value:"'gforge' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);