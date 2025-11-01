# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67267");
  script_cve_id("CVE-2009-2042", "CVE-2010-0205");
  script_tag(name:"creation_date", value:"2010-04-21 01:31:17 +0000 (Wed, 21 Apr 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2032)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2032");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2032");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpng' package(s) announced via the DSA-2032 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in libpng, a library for reading and writing PNG files. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2042

libpng does not properly parse 1-bit interlaced images with width values that are not divisible by 8, which causes libpng to include uninitialized bits in certain rows of a PNG file and might allow remote attackers to read portions of sensitive memory via 'out-of-bounds pixels' in the file.

CVE-2010-0205

libpng does not properly handle compressed ancillary-chunk data that has a disproportionately large uncompressed representation, which allows remote attackers to cause a denial of service (memory and CPU consumption, and application hang) via a crafted PNG file

For the stable distribution (lenny), these problems have been fixed in version 1.2.27-2+lenny3.

For the testing (squeeze) and unstable (sid) distribution, these problems have been fixed in version 1.2.43-1

We recommend that you upgrade your libpng package.");

  script_tag(name:"affected", value:"'libpng' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);