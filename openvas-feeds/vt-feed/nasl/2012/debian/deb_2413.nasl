# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71140");
  script_cve_id("CVE-2011-1777", "CVE-2011-1778");
  script_tag(name:"creation_date", value:"2012-03-12 15:31:25 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2413)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2413");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2413");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libarchive' package(s) announced via the DSA-2413 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two buffer overflows have been discovered in libarchive, a library providing a flexible interface for reading and writing archives in various formats. The possible buffer overflows while reading ISO 9660 or tar streams allow remote attackers to execute arbitrary code depending on the application that makes use of this functionality.

For the stable distribution (squeeze), this problem has been fixed in version 2.8.4-1+squeeze1.

For the testing (wheezy) and unstable (sid) distributions, this problem has been fixed in version 2.8.5-5.

We recommend that you upgrade your libarchive packages.");

  script_tag(name:"affected", value:"'libarchive' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);