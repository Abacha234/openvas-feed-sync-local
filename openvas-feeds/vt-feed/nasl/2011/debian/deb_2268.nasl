# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69975");
  script_cve_id("CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2365", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2376", "CVE-2011-2605");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2268)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2268");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2268");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel, xulrunner' package(s) announced via the DSA-2268 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in Iceweasel, a web browser based on Firefox:

CVE-2011-0083 / CVE-2011-2363 regenrecht discovered two use-after-frees in SVG processing, which could lead to the execution of arbitrary code.

CVE-2011-0085

regenrecht discovered a use-after-free in XUL processing, which could lead to the execution of arbitrary code.

CVE-2011-2362

David Chan discovered that cookies were insufficiently isolated.

CVE-2011-2371

Chris Rohlf and Yan Ivnitskiy discovered an integer overflow in the JavaScript engine, which could lead to the execution of arbitrary code.

CVE-2011-2373

Martin Barbella discovered a use-after-free in XUL processing, which could lead to the execution of arbitrary code.

CVE-2011-2374

Bob Clary, Kevin Brosnan, Nils, Gary Kwong, Jesse Ruderman and Christian Biesinger discovered memory corruption bugs, which may lead to the execution of arbitrary code.

CVE-2011-2376

Luke Wagner and Gary Kwong discovered memory corruption bugs, which may lead to the execution of arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in version 1.9.0.19-12 of the xulrunner source package.

For the stable distribution (squeeze), this problem has been fixed in version 3.5.16-8.

For the unstable distribution (sid), this problem has been fixed in version 3.5.19-3.

For the experimental distribution, this problem has been fixed in version 5.0-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel, xulrunner' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);