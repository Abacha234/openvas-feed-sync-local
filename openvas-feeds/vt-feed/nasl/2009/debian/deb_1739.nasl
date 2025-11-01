# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63604");
  script_cve_id("CVE-2009-0753");
  script_tag(name:"creation_date", value:"2009-03-19 23:52:38 +0000 (Thu, 19 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1739)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1739");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1739");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mldonkey' package(s) announced via the DSA-1739 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that mldonkey, a client for several P2P networks, allows attackers to download arbitrary files using crafted requests to the HTTP console.

The old stable distribution (etch) is not affected by this problem.

For the stable distribution (lenny), this problem has been fixed in version 2.9.5-2+lenny1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your mldonkey packages.");

  script_tag(name:"affected", value:"'mldonkey' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);