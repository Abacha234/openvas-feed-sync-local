# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66146");
  script_cve_id("CVE-2009-3007", "CVE-2009-3274", "CVE-2009-3370", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3382", "CVE-2009-3385");
  script_tag(name:"creation_date", value:"2009-11-11 14:56:44 +0000 (Wed, 11 Nov 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1922)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1922");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1922");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1922 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications, such as the Iceweasel web browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-3380

Vladimir Vukicevic, Jesse Ruderman, Martijn Wargers, Daniel Banchero, David Keeler and Boris Zbarsky reported crashes in layout engine, which might allow the execution of arbitrary code.

CVE-2009-3382

Carsten Book reported a crash in the layout engine, which might allow the execution of arbitrary code.

CVE-2009-3376

Jesse Ruderman and Sid Stamm discovered spoofing vulnerability in the file download dialog.

CVE-2009-3375

Gregory Fleischer discovered a bypass of the same-origin policy using the document.getSelection() function.

CVE-2009-3374

'moz_bug_r_a4' discovered a privilege escalation to Chrome status in the XPCOM utility XPCVariant::VariantDataToJS.

CVE-2009-3373

'regenrecht' discovered a buffer overflow in the GIF parser, which might lead to the execution of arbitrary code.

CVE-2009-3372

Marco C. discovered that a programming error in the proxy auto configuration code might lead to denial of service or the execution of arbitrary code.

CVE-2009-3274

Jeremy Brown discovered that the filename of a downloaded file which is opened by the user is predictable, which might lead to tricking the user into a malicious file if the attacker has local access to the system.

CVE-2009-3370

Paul Stone discovered that history information from web forms could be stolen.

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.15-0lenny1.

As indicated in the Etch release notes, security support for the Mozilla products in the oldstable distribution needed to be stopped before the end of the regular Etch security maintenance life cycle. You are strongly encouraged to upgrade to stable or switch to a still supported browser.

For the unstable distribution (sid), these problems have been fixed in version 1.9.1.4-1.

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);