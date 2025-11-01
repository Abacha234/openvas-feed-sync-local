# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61781");
  script_cve_id("CVE-2008-2469");
  script_tag(name:"creation_date", value:"2008-11-01 00:55:10 +0000 (Sat, 01 Nov 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1659)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1659");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1659");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libspf2' package(s) announced via the DSA-1659 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Kaminsky discovered that libspf2, an implementation of the Sender Policy Framework (SPF) used by mail servers for mail filtering, handles malformed TXT records incorrectly, leading to a buffer overflow condition (CVE-2008-2469).

Note that the SPF configuration template in Debian's Exim configuration recommends to use libmail-spf-query-perl, which does not suffer from this issue.

For the stable distribution (etch), this problem has been fixed in version 1.2.5-4+etch1.

For the testing distribution (lenny), this problem has been fixed in version 1.2.5.dfsg-5+lenny1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your libspf2 package.");

  script_tag(name:"affected", value:"'libspf2' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);