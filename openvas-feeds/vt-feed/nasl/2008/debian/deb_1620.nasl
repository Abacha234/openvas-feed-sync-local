# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61372");
  script_cve_id("CVE-2007-2052", "CVE-2007-4965", "CVE-2008-1679", "CVE-2008-1721", "CVE-2008-1887");
  script_tag(name:"creation_date", value:"2008-08-15 13:52:52 +0000 (Fri, 15 Aug 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1620)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1620");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1620");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python2.5' package(s) announced via the DSA-1620 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the interpreter for the Python language. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2052

Piotr Engelking discovered that the strxfrm() function of the locale module miscalculates the length of an internal buffer, which may result in a minor information disclosure.

CVE-2007-4965

It was discovered that several integer overflows in the imageop module may lead to the execution of arbitrary code, if a user is tricked into processing malformed images. This issue is also tracked as CVE-2008-1679 due to an initially incomplete patch.

CVE-2008-1721

Justin Ferguson discovered that a buffer overflow in the zlib module may lead to the execution of arbitrary code.

CVE-2008-1887

Justin Ferguson discovered that insufficient input validation in PyString_FromStringAndSize() may lead to the execution of arbitrary code.

For the stable distribution (etch), these problems have been fixed in version 2.5-5+etch1.

For the unstable distribution (sid), these problems have been fixed in version 2.5.2-3.

We recommend that you upgrade your python2.5 packages.");

  script_tag(name:"affected", value:"'python2.5' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);