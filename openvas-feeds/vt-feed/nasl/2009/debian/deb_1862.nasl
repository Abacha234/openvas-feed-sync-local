# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64745");
  script_cve_id("CVE-2009-2692");
  script_tag(name:"creation_date", value:"2009-09-02 02:58:39 +0000 (Wed, 02 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1862)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1862");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1862");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1862 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been discovered in the Linux kernel that may lead to privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problem:

CVE-2009-2692

Tavis Ormandy and Julien Tinnes discovered an issue with how the sendpage function is initialized in the proto_ops structure. Local users can exploit this vulnerability to gain elevated privileges.

For the oldstable distribution (etch), this problem will be fixed in updates to linux-2.6 and linux-2.6.24.

For the stable distribution (lenny), this problem has been fixed in version 2.6.26-17lenny2.

We recommend that you upgrade your linux-2.6 and user-mode-linux packages.

Note: Debian carefully tracks all known security issues across every linux kernel package in all releases under active security support. However, given the high frequency at which low-severity security issues are discovered in the kernel and the resource requirements of doing an update, updates for lower priority issues will normally not be released for all kernels at the same time. Rather, they will be released in a staggered or 'leap-frog' fashion.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);