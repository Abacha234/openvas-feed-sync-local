# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63534");
  script_cve_id("CVE-2009-0366", "CVE-2009-0367", "CVE-2009-0878");
  script_tag(name:"creation_date", value:"2009-03-13 18:24:56 +0000 (Fri, 13 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1737)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1737");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1737");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wesnoth' package(s) announced via the DSA-1737 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been discovered in wesnoth, a fantasy turn-based strategy game. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0366

Daniel Franke discovered that the wesnoth server is prone to a denial of service attack when receiving special crafted compressed data.

CVE-2009-0367

Daniel Franke discovered that the sandbox implementation for the python AIs can be used to execute arbitrary python code on wesnoth clients. In order to prevent this issue, the python support has been disabled. A compatibility patch was included, so that the affected campagne is still working properly.

For the stable distribution (lenny), these problems have been fixed in version 1.4.4-2+lenny1.

For the oldstable distribution (etch), these problems have been fixed in version 1.2-5.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 1.4.7-4.

We recommend that you upgrade your wesnoth packages.");

  script_tag(name:"affected", value:"'wesnoth' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);