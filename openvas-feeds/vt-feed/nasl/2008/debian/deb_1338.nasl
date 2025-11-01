# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58470");
  script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738", "CVE-2007-4038");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1338)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1338");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1338");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-1338 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Iceweasel web browser, an unbranded version of the Firefox browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3089

Ronen Zilberman and Michal Zalewski discovered that a timing race allows the injection of content into about:blank frames.

CVE-2007-3656

Michal Zalewski discovered that same-origin policies for wyciwyg:// documents are insufficiently enforced.

CVE-2007-3734

Bernd Mielke, Boris Zbarsky, David Baron, Daniel Veditz, Jesse Ruderman, Lukas Loehrer, Martijn Wargers, Mats Palmgren, Olli Pettay, Paul Nickerson and Vladimir Sukhoy discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2007-3735

Asaf Romano, Jesse Ruderman and Igor Bukanov discovered crashes in the javascript engine, which might allow the execution of arbitrary code.

CVE-2007-3736

moz_bug_r_a4 discovered that the addEventListener() and setTimeout() functions allow cross-site scripting.

CVE-2007-3737

moz_bug_r_a4 discovered that a programming error in event handling allows privilege escalation.

CVE-2007-3738

shutdown and moz_bug_r_a4 discovered that the XPCNativeWrapper allows the execution of arbitrary code.

The Mozilla products in the oldstable distribution (sarge) are no longer supported with security updates. You're strongly encouraged to upgrade to stable as soon as possible.

For the stable distribution (etch) these problems have been fixed in version 2.0.0.5-0etch1. Builds for alpha and mips are not yet available, they will be provided later.

For the unstable distribution (sid) these problems have been fixed in version 2.0.0.5-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);