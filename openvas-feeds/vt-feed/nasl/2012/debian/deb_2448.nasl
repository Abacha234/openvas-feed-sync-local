# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71252");
  script_cve_id("CVE-2012-1836");
  script_tag(name:"creation_date", value:"2012-04-30 11:56:02 +0000 (Mon, 30 Apr 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2448)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2448");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2448");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'inspircd' package(s) announced via the DSA-2448 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a heap-based buffer overflow in InspIRCd could allow remote attackers to execute arbitrary code via a crafted DNS query.

For the stable distribution (squeeze), this problem has been fixed in version 1.1.22+dfsg-4+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 1.1.22+dfsg-4+wheezy1.

For the unstable distribution (sid), this problem has been fixed in version 2.0.5-0.1.

We recommend that you upgrade your inspircd packages.");

  script_tag(name:"affected", value:"'inspircd' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);