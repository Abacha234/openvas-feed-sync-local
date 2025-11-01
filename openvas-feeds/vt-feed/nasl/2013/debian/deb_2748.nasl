# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702748");
  script_cve_id("CVE-2013-1438");
  script_tag(name:"creation_date", value:"2013-08-31 22:00:00 +0000 (Sat, 31 Aug 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2748)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2748");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2748");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exactimage' package(s) announced via the DSA-2748 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several denial-of-service vulnerabilities were discovered in the dcraw code base, a program for processing raw format images from digital cameras. This update corrects them in the copy that is embedded in the exactimage package.

For the oldstable distribution (squeeze), this problem has been fixed in version 0.8.1-3+deb6u2.

For the stable distribution (wheezy), this problem has been fixed in version 0.8.5-5+deb7u2.

For the unstable distribution (sid), this problem has been fixed in version 0.8.9-1.

We recommend that you upgrade your exactimage packages.");

  script_tag(name:"affected", value:"'exactimage' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);