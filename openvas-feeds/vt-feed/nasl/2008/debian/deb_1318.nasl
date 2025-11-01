# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58424");
  script_cve_id("CVE-2005-2370", "CVE-2005-2448", "CVE-2007-1663", "CVE-2007-1664", "CVE-2007-1665");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1318)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1318");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1318");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ekg' package(s) announced via the DSA-1318 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in ekg, a console Gadu Gadu client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-2370

It was discovered that memory alignment errors may allow remote attackers to cause a denial of service on certain architectures such as sparc. This only affects Debian Sarge.

CVE-2005-2448

It was discovered that several endianness errors may allow remote attackers to cause a denial of service. This only affects Debian Sarge.

CVE-2007-1663

It was discovered that a memory leak in handling image messages may lead to denial of service. This only affects Debian Etch.

CVE-2007-1664

It was discovered that a null pointer deference in the token OCR code may lead to denial of service. This only affects Debian Etch.

CVE-2007-1665

It was discovered that a memory leak in the token OCR code may lead to denial of service. This only affects Debian Etch.

For the oldstable distribution (sarge) these problems have been fixed in version 1.5+20050411-7. This updates lacks updated packages for the m68k architecture. They will be provided later.

For the stable distribution (etch) these problems have been fixed in version 1:1.7~rc2-1etch1.

For the unstable distribution (sid) these problems have been fixed in version 1:1.7~rc2-2.

We recommend that you upgrade your ekg packages.");

  script_tag(name:"affected", value:"'ekg' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);