# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60796");
  script_cve_id("CVE-2008-0314", "CVE-2008-1100", "CVE-2008-1833");
  script_tag(name:"creation_date", value:"2008-04-21 18:40:14 +0000 (Mon, 21 Apr 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1549)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1549");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1549");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DSA-1549 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Clam anti-virus toolkit. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0314

Damian Put discovered that a buffer overflow in the handler for PeSpin binaries may lead to the execution of arbitrary code.

CVE-2008-1100

Alin Rad Pop discovered that a buffer overflow in the handler for Upack PE binaries may lead to the execution of arbitrary code.

CVE-2008-1833

Damian Put and Thomas Pollet discovered that a buffer overflow in the handler for WWPack-compressed PE binaries may lead to the execution of arbitrary code.

For the stable distribution (etch) these problems have been fixed in version 0.90.1dfsg-3etch11.

For the unstable distribution (sid) these problems have been fixed in version 0.92.1~dfsg2-1.

We recommend that you upgrade your clamav packages.");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);