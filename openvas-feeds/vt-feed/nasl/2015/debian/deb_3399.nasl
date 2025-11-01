# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703399");
  script_cve_id("CVE-2015-7981", "CVE-2015-8126");
  script_tag(name:"creation_date", value:"2015-11-17 23:00:00 +0000 (Tue, 17 Nov 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3399)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3399");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3399");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpng' package(s) announced via the DSA-3399 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the libpng PNG library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-7981

Qixue Xiao discovered an out-of-bounds read vulnerability in the png_convert_to_rfc1123 function. A remote attacker can potentially take advantage of this flaw to cause disclosure of information from process memory.

CVE-2015-8126

Multiple buffer overflows were discovered in the png_set_PLTE and png_get_PLTE functions. A remote attacker can take advantage of this flaw to cause a denial of service (application crash) via a small bit-depth value in an IHDR (image header) chunk in a PNG image.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.2.49-1+deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 1.2.50-2+deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 1.2.54-1.

We recommend that you upgrade your libpng packages.");

  script_tag(name:"affected", value:"'libpng' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);