# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57567");
  script_cve_id("CVE-2005-3353", "CVE-2006-3017", "CVE-2006-4482", "CVE-2006-5465");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1206)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1206");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1206");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php4' package(s) announced via the DSA-1206 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in PHP, a server-side, HTML-embedded scripting language, which may lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-3353

Tim Starling discovered that missing input sanitising in the EXIF module could lead to denial of service.

CVE-2006-3017

Stefan Esser discovered a security-critical programming error in the hashtable implementation of the internal Zend engine.

CVE-2006-4482

It was discovered that str_repeat() and wordwrap() functions perform insufficient checks for buffer boundaries on 64 bit systems, which might lead to the execution of arbitrary code.

CVE-2006-5465

Stefan Esser discovered a buffer overflow in the htmlspecialchars() and htmlentities(), which might lead to the execution of arbitrary code.

For the stable distribution (sarge) these problems have been fixed in version 4:4.3.10-18. Builds for hppa and m68k will be provided later once they are available.

For the unstable distribution (sid) these problems have been fixed in version 4:4.4.4-4 of php4 and version 5.1.6-6 of php5.

We recommend that you upgrade your php4 packages.");

  script_tag(name:"affected", value:"'php4' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);