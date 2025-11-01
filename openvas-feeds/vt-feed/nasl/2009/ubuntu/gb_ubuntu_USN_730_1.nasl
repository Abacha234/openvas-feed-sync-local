# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63513");
  script_cve_id("CVE-2007-5268", "CVE-2007-5269", "CVE-2008-1382", "CVE-2008-3964", "CVE-2008-5907", "CVE-2009-0040");
  script_tag(name:"creation_date", value:"2009-03-07 20:47:03 +0000 (Sat, 07 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-730-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-730-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-730-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng' package(s) announced via the USN-730-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libpng did not properly perform bounds checking in
certain operations. An attacker could send a specially crafted PNG image and
cause a denial of service in applications linked against libpng. This issue
only affected Ubuntu 8.04 LTS. (CVE-2007-5268, CVE-2007-5269)

Tavis Ormandy discovered that libpng did not properly initialize memory. If a
user or automated system were tricked into opening a crafted PNG image, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the program.
This issue did not affect Ubuntu 8.10. (CVE-2008-1382)

Harald van Dijk discovered an off-by-one error in libpng. An attacker could
could cause an application crash in programs using pngtest. (CVE-2008-3964)

It was discovered that libpng did not properly NULL terminate a keyword
string. An attacker could exploit this to set arbitrary memory locations to
zero. (CVE-2008-5907)

Glenn Randers-Pehrson discovered that libpng did not properly initialize
pointers. If a user or automated system were tricked into opening a crafted PNG
file, an attacker could cause a denial of service or possibly execute arbitrary
code with the privileges of the user invoking the program. (CVE-2009-0040)");

  script_tag(name:"affected", value:"'libpng' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
