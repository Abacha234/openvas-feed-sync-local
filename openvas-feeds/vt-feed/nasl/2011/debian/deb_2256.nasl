# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69963");
  script_cve_id("CVE-2009-5022");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2256)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2256");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2256");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DSA-2256 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered that the Tag Image File Format (TIFF) library is vulnerable to a buffer overflow triggered by a crafted OJPEG file which allows for a crash and potentially execution of arbitrary code.

The oldstable distribution (lenny) is not affected by this problem.

For the stable distribution (squeeze), this problem has been fixed in version 3.9.4-5+squeeze2.

For the testing distribution (wheezy) and unstable distribution (sid), this problem has been fixed in version 3.9.5-1.

We recommend that you upgrade your tiff packages.");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);