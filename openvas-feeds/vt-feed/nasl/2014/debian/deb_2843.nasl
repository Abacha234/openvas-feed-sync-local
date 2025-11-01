# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702843");
  script_cve_id("CVE-2014-0978", "CVE-2014-1236");
  script_tag(name:"creation_date", value:"2014-01-12 23:00:00 +0000 (Sun, 12 Jan 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2843)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2843");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2843");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphviz' package(s) announced via the DSA-2843 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two buffer overflow vulnerabilities were reported in Graphviz, a rich collection of graph drawing tools. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2014-0978

It was discovered that user-supplied input used in the yyerror() function in lib/cgraph/scan.l is not bound-checked before being copied into an insufficiently sized memory buffer. A context-dependent attacker could supply a specially crafted input file containing a long line to cause a stack-based buffer overflow, resulting in a denial of service (application crash) or potentially allowing the execution of arbitrary code.

CVE-2014-1236

Sebastian Krahmer reported an overflow condition in the chkNum() function in lib/cgraph/scan.l that is triggered as the used regular expression accepts an arbitrary long digit list. With a specially crafted input file, a context-dependent attacker can cause a stack-based buffer overflow, resulting in a denial of service (application crash) or potentially allowing the execution of arbitrary code.

For the oldstable distribution (squeeze), these problems have been fixed in version 2.26.3-5+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in version 2.26.3-14+deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your graphviz packages.");

  script_tag(name:"affected", value:"'graphviz' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);