# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72173");
  script_cve_id("CVE-2012-3494", "CVE-2012-3496");
  script_tag(name:"creation_date", value:"2012-09-15 08:24:09 +0000 (Sat, 15 Sep 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2544)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2544");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2544");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-2544 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple denial of service vulnerabilities have been discovered in Xen, an hypervisor. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-3494: It was discovered that set_debugreg allows writes to reserved bits of the DR7 debug control register on amd64 (x86-64) paravirtualised guests, allowing a guest to crash the host.

CVE-2012-3496: Matthew Daley discovered that XENMEM_populate_physmap, when called with the MEMF_populate_on_demand flag set, a BUG (detection routine) can be triggered if a translating paging mode is not being used, allowing a guest to crash the host.

For the stable distribution (squeeze), these problems have been fixed in version 4.0.1-5.4.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 4.1.3-2.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);