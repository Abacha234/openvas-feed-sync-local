# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66951");
  script_cve_id("CVE-2009-1571", "CVE-2009-3988", "CVE-2010-0159", "CVE-2010-0162", "CVE-2010-0167", "CVE-2010-0169", "CVE-2010-0171");
  script_tag(name:"creation_date", value:"2010-02-25 21:02:04 +0000 (Thu, 25 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1999)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1999");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1999");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1999 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications, such as the Iceweasel web browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1571

Alin Rad Pop discovered that incorrect memory handling in the HTML parser could lead to the execution of arbitrary code.

CVE-2009-3988

Hidetake Jo discovered that the same-origin policy can be bypassed through window.dialogArguments.

CVE-2010-0159

Henri Sivonen, Boris Zbarsky, Zack Weinberg, Bob Clary, Martijn Wargers and Paul Nickerson reported crashes in layout engine, which might allow the execution of arbitrary code.

CVE-2010-0160

Orlando Barrera II discovered that incorrect memory handling in the implementation of the web worker API could lead to the execution of arbitrary code.

CVE-2010-0162

Georgi Guninski discovered that the same origin policy can be bypassed through specially crafted SVG documents.

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.18-1.

For the unstable distribution (sid), these problems have been fixed in version 1.9.1.8-1.

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);