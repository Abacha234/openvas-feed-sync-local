# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58333");
  script_cve_id("CVE-2007-1745", "CVE-2007-1997", "CVE-2007-2029");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1281)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1281");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1281");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DSA-1281 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Clam anti-virus toolkit. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1745

It was discovered that a file descriptor leak in the CHM handler may lead to denial of service.

CVE-2007-1997

It was discovered that a buffer overflow in the CAB handler may lead to the execution of arbitrary code.

CVE-2007-2029

It was discovered that a file descriptor leak in the PDF handler may lead to denial of service.

For the oldstable distribution (sarge) these problems have been fixed in version 0.84-2.sarge.16.

For the stable distribution (etch) these problems have been fixed in version 0.90.1-3etch1.

For the unstable distribution (sid) these problems have been fixed in version 0.90.2-1.

We recommend that you upgrade your clamav packages. Packages for the arm, sparc, m68k, mips and mipsel architectures are not yet available. They will be provided later.");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);