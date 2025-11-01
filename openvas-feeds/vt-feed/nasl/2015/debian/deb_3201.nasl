# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703201");
  script_cve_id("CVE-2015-0817", "CVE-2015-0818");
  script_tag(name:"creation_date", value:"2015-03-21 23:00:00 +0000 (Sat, 21 Mar 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3201)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3201");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3201");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-3201 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Iceweasel, Debian's version of the Mozilla Firefox web browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-0817

ilxu1a reported a flaw in Mozilla's implementation of typed array bounds checking in JavaScript just-in-time compilation (JIT) and its management of bounds checking for heap access. This flaw can be leveraged into the reading and writing of memory allowing for arbitrary code execution on the local system.

CVE-2015-0818

Mariusz Mlynski discovered a method to run arbitrary scripts in a privileged context. This bypassed the same-origin policy protections by using a flaw in the processing of SVG format content navigation.

For the stable distribution (wheezy), these problems have been fixed in version 31.5.3esr-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 31.5.3esr-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);