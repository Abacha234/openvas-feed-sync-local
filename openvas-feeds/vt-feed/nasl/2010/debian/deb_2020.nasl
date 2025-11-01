# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67125");
  script_cve_id("CVE-2010-1195");
  script_tag(name:"creation_date", value:"2010-03-30 16:37:46 +0000 (Tue, 30 Mar 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2020)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2020");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2020");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ikiwiki' package(s) announced via the DSA-2020 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ivan Shmakov discovered that the htmlscrubber component of ikiwiki, a wiki compiler, performs insufficient input sanitization on data:image/svg+xml URIs. As these can contain script code this can be used by an attacker to conduct cross-site scripting attacks.

For the stable distribution (lenny), this problem has been fixed in version 2.53.5.

For the testing distribution (squeeze), this problem has been fixed in version 3.20100312.

For the unstable distribution (sid), this problem has been fixed in version 3.20100312.");

  script_tag(name:"affected", value:"'ikiwiki' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);