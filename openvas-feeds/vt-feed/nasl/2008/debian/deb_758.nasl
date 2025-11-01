# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54369");
  script_cve_id("CVE-2005-2040");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-758)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-758");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-758");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'heimdal' package(s) announced via the DSA-758 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow has been discovered in the telnet server from Heimdal, a free implementation of Kerberos 5, that could lead to the execution of arbitrary code.

For the old stable distribution (woody) this problem has been fixed in version 0.4e-7.woody.10.

For the stable distribution (sarge) this problem has been fixed in version 0.6.3-10sarge1.

For the unstable distribution (sid) this problem has been fixed in version 0.6.3-11.

We recommend that you upgrade your heimdal packages.");

  script_tag(name:"affected", value:"'heimdal' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);