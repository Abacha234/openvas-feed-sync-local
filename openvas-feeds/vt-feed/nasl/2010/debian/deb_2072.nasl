# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67828");
  script_cve_id("CVE-2010-1205", "CVE-2010-2249");
  script_tag(name:"creation_date", value:"2010-08-21 06:54:16 +0000 (Sat, 21 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:50:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-2072)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2072");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2072");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpng' package(s) announced via the DSA-2072 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in libpng, a library for reading and writing PNG files. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-1205

It was discovered a buffer overflow in libpng which allows remote attackers to execute arbitrary code via a PNG image that triggers an additional data row.

CVE-2010-2249

It was discovered a memory leak in libpng which allows remote attackers to cause a denial of service (memory consumption and application crash) via a PNG image containing malformed Physical Scale (aka sCAL) chunks.

For the stable distribution (lenny), these problems have been fixed in version 1.2.27-2+lenny4.

For the testing (squeeze) and unstable (sid) distribution, these problems have been fixed in version 1.2.44-1.

We recommend that you upgrade your libpng package.");

  script_tag(name:"affected", value:"'libpng' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);