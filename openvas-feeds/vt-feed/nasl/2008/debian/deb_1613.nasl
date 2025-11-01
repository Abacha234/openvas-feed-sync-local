# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61363");
  script_cve_id("CVE-2007-2445", "CVE-2007-2756", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3996");
  script_tag(name:"creation_date", value:"2008-08-15 13:52:52 +0000 (Fri, 15 Aug 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1613)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1613");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1613");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libgd2' package(s) announced via the DSA-1613 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been identified in libgd2, a library for programmatic graphics creation and manipulation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2445

Grayscale PNG files containing invalid tRNS chunk CRC values could cause a denial of service (crash), if a maliciously crafted image is loaded into an application using libgd.

CVE-2007-3476

An array indexing error in libgd's GIF handling could induce a denial of service (crash with heap corruption) if exceptionally large color index values are supplied in a maliciously crafted GIF image file.

CVE-2007-3477

The imagearc() and imagefilledarc() routines in libgd allow an attacker in control of the parameters used to specify the degrees of arc for those drawing functions to perform a denial of service attack (excessive CPU consumption).

CVE-2007-3996

Multiple integer overflows exist in libgd's image resizing and creation routines, these weaknesses allow an attacker in control of the parameters passed to those routines to induce a crash or execute arbitrary code with the privileges of the user running an application or interpreter linked against libgd2.

For the stable distribution (etch), these problems have been fixed in version 2.0.33-5.2etch1.

For the unstable distribution (sid), these problems have been fixed in version 2.0.35.dfsg-1.

We recommend that you upgrade your libgd2 packages.");

  script_tag(name:"affected", value:"'libgd2' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);