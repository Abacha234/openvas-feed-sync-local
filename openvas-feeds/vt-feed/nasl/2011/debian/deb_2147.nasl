# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68983");
  script_cve_id("CVE-2011-0007");
  script_tag(name:"creation_date", value:"2011-03-07 15:04:02 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2147)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2147");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2147");
  script_xref(name:"URL", value:"https://www.debian.org/security/");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pimd' package(s) announced via the DSA-2147 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vincent Bernat discovered that pimd, a multicast routing daemon, creates files with predictable names upon the receipt of particular signals.

For the stable distribution (lenny), this problem has been fixed in version 2.1.0-alpha29.17-8.1lenny1.

The testing distribution (squeeze) and the unstable distribution (sid) will receive updates shortly.

We recommend that you upgrade your pimd packages.

Further information about Debian Security Advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'pimd' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);