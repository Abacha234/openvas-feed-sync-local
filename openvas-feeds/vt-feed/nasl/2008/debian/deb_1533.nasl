# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60659");
  script_cve_id("CVE-2007-6354", "CVE-2007-6355", "CVE-2007-6356");
  script_tag(name:"creation_date", value:"2008-04-07 18:38:54 +0000 (Mon, 07 Apr 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1533)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1533");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1533");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exiftags' package(s) announced via the DSA-1533 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Schmid and Meder Kydyraliev (Google Security) discovered a number of vulnerabilities in exiftags, a utility for extracting EXIF metadata from JPEG images. The Common Vulnerabilities and Exposures project identified the following three problems:

CVE-2007-6354

Inadequate EXIF property validation could lead to invalid memory accesses if executed on a maliciously crafted image, potentially including heap corruption and the execution of arbitrary code.

CVE-2007-6355

Flawed data validation could lead to integer overflows, causing other invalid memory accesses, also with the potential for memory corruption or arbitrary code execution.

CVE-2007-6356

Cyclical EXIF image file directory (IFD) references could cause a denial of service (infinite loop).

For the oldstable distribution (sarge), these problems have been fixed in version 0.98-1.1+0sarge1.

For the stable distribution (etch), these problems have been fixed in version 0.98-1.1+etch1.

For the unstable distribution (sid), these problems have been fixed in version 1.01-0.1.");

  script_tag(name:"affected", value:"'exiftags' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);