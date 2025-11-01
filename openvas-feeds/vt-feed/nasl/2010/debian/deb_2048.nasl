# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67402");
  script_cve_id("CVE-2010-0829");
  script_tag(name:"creation_date", value:"2010-06-03 20:55:24 +0000 (Thu, 03 Jun 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2048)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2048");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2048");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dvipng' package(s) announced via the DSA-2048 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that in dvipng, a utility that converts DVI files to PNG graphics, several array index errors allow context-dependent attackers, via a specially crafted DVI file, to cause a denial of service (crash of the application), and possibly arbitrary code execution.

For the stable distribution (lenny), this problem has been fixed in version dvipng_1.11-1+lenny1.

For the testing distribution (squeeze), this problem has been fixed in version 1.13-1.

For the unstable distribution (sid), this problem has been fixed in version 1.13-1.

We recommend that you upgrade your dvipng package.");

  script_tag(name:"affected", value:"'dvipng' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);