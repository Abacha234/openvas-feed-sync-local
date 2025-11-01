# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66771");
  script_cve_id("CVE-2006-4334", "CVE-2009-2624", "CVE-2010-0001");
  script_tag(name:"creation_date", value:"2010-02-01 17:25:19 +0000 (Mon, 01 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1974)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1974");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1974");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gzip' package(s) announced via the DSA-1974 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in gzip, the GNU compression utilities. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2624

Thiemo Nagel discovered a missing input sanitation flaw in the way gzip used to decompress data blocks for dynamic Huffman codes, which could lead to the execution of arbitrary code when trying to decompress a crafted archive. This issue is a reappearance of CVE-2006-4334 and only affects the lenny version.

CVE-2010-0001

Aki Helin discovered an integer underflow when decompressing files that are compressed using the LZW algorithm. This could lead to the execution of arbitrary code when trying to decompress a crafted LZW compressed gzip archive.

For the stable distribution (lenny), these problems have been fixed in version 1.3.12-6+lenny1.

For the oldstable distribution (etch), these problems have been fixed in version 1.3.5-15+etch1.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your gzip packages.");

  script_tag(name:"affected", value:"'gzip' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);