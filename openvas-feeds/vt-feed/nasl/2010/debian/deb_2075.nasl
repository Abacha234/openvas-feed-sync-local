# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67832");
  script_cve_id("CVE-2010-0182", "CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1208", "CVE-2010-1211", "CVE-2010-1214", "CVE-2010-2751", "CVE-2010-2753", "CVE-2010-2754");
  script_tag(name:"creation_date", value:"2010-08-21 06:54:16 +0000 (Sat, 21 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:50:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-2075)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2075");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2075");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-2075 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-0182

Wladimir Palant discovered that security checks in XML processing were insufficiently enforced.

CVE-2010-0654

Chris Evans discovered that insecure CSS handling could lead to reading data across domain boundaries.

CVE-2010-1205

Aki Helin discovered a buffer overflow in the internal copy of libpng, which could lead to the execution of arbitrary code.

CVE-2010-1208

'regenrecht' discovered that incorrect memory handling in DOM parsing could lead to the execution of arbitrary code.

CVE-2010-1211

Jesse Ruderman, Ehsan Akhgari, Mats Palmgren, Igor Bukanov, Gary Kwong, Tobias Markus and Daniel Holbert discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2010-1214

'JS3' discovered an integer overflow in the plugin code, which could lead to the execution of arbitrary code.

CVE-2010-2751

Jordi Chancel discovered that the location could be spoofed to appear like a secured page.

CVE-2010-2753

'regenrecht' discovered that incorrect memory handling in XUL parsing could lead to the execution of arbitrary code.

CVE-2010-2754

Soroush Dalili discovered an information leak in script processing.

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.19-3.

For the unstable distribution (sid), these problems have been fixed in version 1.9.1.11-1.

For the experimental distribution, these problems have been fixed in version 1.9.2.7-1.

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);