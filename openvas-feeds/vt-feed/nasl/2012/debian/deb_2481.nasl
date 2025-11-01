# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71461");
  script_cve_id("CVE-2012-2653");
  script_tag(name:"creation_date", value:"2012-08-10 06:56:26 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2481)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2481");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2481");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'arpwatch' package(s) announced via the DSA-2481 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steve Grubb from Red Hat discovered that a patch for arpwatch (as shipped at least in Red Hat and Debian distributions) in order to make it drop root privileges would fail to do so and instead add the root group to the list of the daemon uses.

For the stable distribution (squeeze), this problem has been fixed in version 2.1a15-1.1+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 2.1a15-1.2.

For the unstable distribution (sid), this problem has been fixed in version 2.1a15-1.2.

We recommend that you upgrade your arpwatch packages.");

  script_tag(name:"affected", value:"'arpwatch' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);