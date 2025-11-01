# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67397");
  script_cve_id("CVE-2010-2062");
  script_tag(name:"creation_date", value:"2010-06-03 20:55:24 +0000 (Thu, 03 Jun 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2043)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2043");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2043");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vlc' package(s) announced via the DSA-2043 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"tixxDZ (DZCORE labs) discovered a vulnerability in vlc, the multimedia player and streamer. Missing data validation in vlc's real data transport (RDT) implementation enable an integer underflow and consequently an unbounded buffer operation. A maliciously crafted stream could thus enable an attacker to execute arbitrary code.

No Common Vulnerabilities and Exposures project identifier is available for this issue.

For the stable distribution (lenny), this problem has been fixed in version 0.8.6.h-4+lenny2.3.

For the testing distribution (squeeze), this problem was fixed in version 1.0.1-1.

We recommend that you upgrade your vlc packages.");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);