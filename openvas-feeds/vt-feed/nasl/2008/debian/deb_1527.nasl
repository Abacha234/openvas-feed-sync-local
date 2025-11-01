# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60617");
  script_cve_id("CVE-2007-3912");
  script_tag(name:"creation_date", value:"2008-03-27 17:25:13 +0000 (Thu, 27 Mar 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1527)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1527");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1527");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'debian-goodies' package(s) announced via the DSA-1527 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thomas de Grenier de Latour discovered that the checkrestart tool in the debian-goodies suite of utilities, allowed local users to gain privileges via shell metacharacters in the name of the executable file for a running process.

For the old stable distribution (sarge), this problem has been fixed in version 0.24+sarge1.

For the stable distribution (etch), this problem has been fixed in version 0.27+etch1.

For the unstable distribution (sid), this problem has been fixed in version 0.34.

We recommend that you upgrade your debian-goodies package.");

  script_tag(name:"affected", value:"'debian-goodies' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);