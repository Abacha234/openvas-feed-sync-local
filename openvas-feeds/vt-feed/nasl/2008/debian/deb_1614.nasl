# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61365");
  script_cve_id("CVE-2008-2785", "CVE-2008-2933", "CVE-2008-3198");
  script_tag(name:"creation_date", value:"2008-08-15 13:52:52 +0000 (Fri, 15 Aug 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1614)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1614");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1614");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-1614 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Iceweasel web browser, an unbranded version of the Firefox browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-2785

It was discovered that missing boundary checks on a reference counter for CSS objects can lead to the execution of arbitrary code.

CVE-2008-2933

Billy Rios discovered that passing an URL containing a pipe symbol to Iceweasel can lead to Chrome privilege escalation.

For the stable distribution (etch), these problems have been fixed in version 2.0.0.16-0etch1. Updated packages for ia64, arm and mips are not yet available and will be released as soon as they have been built.

For the unstable distribution (sid), these problems have been fixed in xulrunner 1.9.0.1-1 and iceweasel 3.0.1-1.

We recommend that you upgrade your iceweasel package.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);