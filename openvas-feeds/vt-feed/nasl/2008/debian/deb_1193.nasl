# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58696");
  script_cve_id("CVE-2006-3467", "CVE-2006-3739", "CVE-2006-3740", "CVE-2006-4447");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1193)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1193");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1193");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xfree86' package(s) announced via the DSA-1193 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the X Window System, which may lead to the execution of arbitrary code or denial of service. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-3467

Chris Evan discovered an integer overflow in the code to handle PCF fonts, which might lead to denial of service if a malformed font is opened.

CVE-2006-3739

It was discovered that an integer overflow in the code to handle Adobe Font Metrics might lead to the execution of arbitrary code.

CVE-2006-3740

It was discovered that an integer overflow in the code to handle CMap and CIDFont font data might lead to the execution of arbitrary code.

CVE-2006-4447

The XFree86 initialization code performs insufficient checking of the return value of setuid() when dropping privileges, which might lead to local privilege escalation.

For the stable distribution (sarge) these problems have been fixed in version 4.3.0.dfsg.1-14sarge2. This release lacks builds for the Motorola 680x0 architecture, which failed due to diskspace constraints on the build host. They will be released once this problem has been resolved.

For the unstable distribution (sid) these problems have been fixed in version 1:1.2.2-1 of libxfont and version 1:1.0.2-9 of xorg-server.

We recommend that you upgrade your XFree86 packages.");

  script_tag(name:"affected", value:"'xfree86' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);