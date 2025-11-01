# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72441");
  script_cve_id("CVE-2012-2186", "CVE-2012-3812", "CVE-2012-3863", "CVE-2012-4737");
  script_tag(name:"creation_date", value:"2012-10-03 15:09:39 +0000 (Wed, 03 Oct 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2550)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2550");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2550");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DSA-2550 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Asterisk, a PBX and telephony toolkit, allowing privilege escalation in the Asterisk Manager, denial of service or privilege escalation.

More detailed information can be found in the Asterisk advisories: AST-2012-010, AST-2012-011, AST-2012-012, and AST-2012-013.

For the stable distribution (squeeze), these problems have been fixed in version 1:1.6.2.9-2+squeeze8.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 1:1.8.13.1~dfsg-1.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);