# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64479");
  script_cve_id("CVE-2009-2462", "CVE-2009-2464", "CVE-2009-2465", "CVE-2009-2466", "CVE-2009-2467", "CVE-2009-2469", "CVE-2009-2470", "CVE-2009-2471", "CVE-2009-2472");
  script_tag(name:"creation_date", value:"2009-07-29 17:28:37 +0000 (Wed, 29 Jul 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1840)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1840");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1840");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1840 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications, such as the Iceweasel web browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2462

Martijn Wargers, Arno Renevier, Jesse Ruderman, Olli Pettay and Blake Kaplan discovered several issues in the browser engine that could potentially lead to the execution of arbitrary code. (MFSA 2009-34)

CVE-2009-2463

monarch2020 reported an integer overflow in a base64 decoding function. (MFSA 2009-34)

CVE-2009-2464

Christophe Charron reported a possibly exploitable crash occurring when multiple RDF files were loaded in a XUL tree element. (MFSA 2009-34)

CVE-2009-2465

Yongqian Li reported that an unsafe memory condition could be created by specially crafted document. (MFSA 2009-34)

CVE-2009-2466

Peter Van der Beken, Mike Shaver, Jesse Ruderman, and Carsten Book discovered several issues in the JavaScript engine that could possibly lead to the execution of arbitrary JavaScript. (MFSA 2009-34)

CVE-2009-2467

Attila Suszter discovered an issue related to a specially crafted Flash object, which could be used to run arbitrary code. (MFSA 2009-35)

CVE-2009-2469

PenPal discovered that it is possible to execute arbitrary code via a specially crafted SVG element. (MFSA 2009-37)

CVE-2009-2471

Blake Kaplan discovered a flaw in the JavaScript engine that might allow an attacker to execute arbitrary JavaScript with chrome privileges. (MFSA 2009-39)

CVE-2009-2472

moz_bug_r_a4 discovered an issue in the JavaScript engine that could be used to perform cross-site scripting attacks. (MFSA 2009-40)

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.12-0lenny1.

As indicated in the Etch release notes, security support for the Mozilla products in the oldstable distribution needed to be stopped before the end of the regular Etch security maintenance life cycle. You are strongly encouraged to upgrade to stable or switch to a still supported browser.

For the testing distribution (squeeze), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 1.9.0.12-1.

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);