# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71237");
  script_cve_id("CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0458", "CVE-2012-0461");
  script_tag(name:"creation_date", value:"2012-04-30 11:54:25 +0000 (Mon, 30 Apr 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2433)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2433");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2433");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-2433 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Iceweasel, a web browser based on Firefox. The included XULRunner library provides rendering services for several other applications included in Debian.

CVE-2012-0455

Soroush Dalili discovered that a cross-site scripting countermeasure related to JavaScript URLs could be bypassed.

CVE-2012-0456

Atte Kettunen discovered an out of bounds read in the SVG Filters, resulting in memory disclosure.

CVE-2012-0458

Mariusz Mlynski discovered that privileges could be escalated through a JavaScript URL as the home page.

CVE-2012-0461

Bob Clary discovered memory corruption bugs, which may lead to the execution of arbitrary code.

For the stable distribution (squeeze), this problem has been fixed in version 3.5.16-13.

For the unstable distribution (sid), this problem has been fixed in version 10.0.3esr-1.

For the experimental distribution, this problem has been fixed in version 11.0-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);