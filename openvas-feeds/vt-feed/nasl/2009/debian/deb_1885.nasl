# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64870");
  script_cve_id("CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078");
  script_tag(name:"creation_date", value:"2009-09-15 20:46:32 +0000 (Tue, 15 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1885)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1885");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1885");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1885 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications, such as the Iceweasel web browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-3070

Jesse Ruderman discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2009-3071

Daniel Holbert, Jesse Ruderman, Olli Pettay and 'toshi' discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2009-3072

Josh Soref, Jesse Ruderman and Martin Wargers discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2009-3074

Jesse Ruderman discovered a crash in the Javascript engine, which might allow the execution of arbitrary code.

CVE-2009-3075

Carsten Book and 'Taral' discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2009-3076

Jesse Ruderman discovered that the user interface for installing/ removing PCKS #11 security modules wasn't informative enough, which might allow social engineering attacks.

CVE-2009-3077

It was discovered that incorrect pointer handling in the XUL parser could lead to the execution of arbitrary code.

CVE-2009-3078

Juan Pablo Lopez Yacubian discovered that incorrect rendering of some Unicode font characters could lead to spoofing attacks on the location bar.

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.14-0lenny1.

As indicated in the Etch release notes, security support for the Mozilla products in the oldstable distribution needed to be stopped before the end of the regular Etch security maintenance life cycle. You are strongly encouraged to upgrade to stable or switch to a still supported browser.

For the unstable distribution (sid), these problems have been fixed in version 1.9.0.14-1.

For the experimental distribution, these problems have been fixed in version 1.9.1.3-1.

We recommend that you upgrade your xulrunner package.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);