# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57709");
  script_cve_id("CVE-2006-6169", "CVE-2006-6235");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1231)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1231");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1231");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnupg' package(s) announced via the DSA-1231 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the GNU privacy guard, a free PGP replacement, which may lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-6169

Werner Koch discovered that a buffer overflow in a sanitising function may lead to execution of arbitrary code when running gnupg interactively.

CVE-2006-6235

Tavis Ormandy discovered that parsing a carefully crafted OpenPGP packet may lead to the execution of arbitrary code, as a function pointer of an internal structure may be controlled through the decryption routines.

For the stable distribution (sarge) these problems have been fixed in version 1.4.1-1.sarge6.

For the upcoming stable distribution (etch) these problems have been fixed in version 1.4.6-1.

For the unstable distribution (sid) these problems have been fixed in version 1.4.6-1.

We recommend that you upgrade your gnupg packages.");

  script_tag(name:"affected", value:"'gnupg' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);