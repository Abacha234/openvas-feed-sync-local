# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67542");
  script_cve_id("CVE-2008-1391", "CVE-2009-4880", "CVE-2009-4881", "CVE-2010-0296", "CVE-2010-0830");
  script_tag(name:"creation_date", value:"2010-06-10 19:49:43 +0000 (Thu, 10 Jun 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2058)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2058");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2058");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'glibc' package(s) announced via the DSA-2058 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the GNU C Library (aka glibc) and its derivatives. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-1391, CVE-2009-4880, CVE-2009-4881 Maksymilian Arciemowicz discovered that the GNU C library did not correctly handle integer overflows in the strfmon family of functions. If a user or automated system were tricked into processing a specially crafted format string, a remote attacker could crash applications, leading to a denial of service.

CVE-2010-0296

Jeff Layton and Dan Rosenberg discovered that the GNU C library did not correctly handle newlines in the mntent family of functions. If a local attacker were able to inject newlines into a mount entry through other vulnerable mount helpers, they could disrupt the system or possibly gain root privileges.

CVE-2010-0830

Dan Rosenberg discovered that the GNU C library did not correctly validate certain ELF program headers. If a user or automated system were tricked into verifying a specially crafted ELF program, a remote attacker could execute arbitrary code with user privileges.

For the stable distribution (lenny), these problems have been fixed in version 2.7-18lenny4 of the glibc package.

For the testing distribution (squeeze), these problems will be fixed soon.

For the unstable distribution (sid), these problems has been fixed in version 2.1.11-1 of the eglibc package.

We recommend that you upgrade your glibc or eglibc packages.");

  script_tag(name:"affected", value:"'glibc' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);