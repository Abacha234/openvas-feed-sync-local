# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63856");
  script_cve_id("CVE-2007-6725", "CVE-2008-6679", "CVE-2009-0196", "CVE-2009-0583", "CVE-2009-0584", "CVE-2009-0792");
  script_tag(name:"creation_date", value:"2009-04-20 21:45:17 +0000 (Mon, 20 Apr 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-757-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-757-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-757-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript, gs-esp, gs-gpl' package(s) announced via the USN-757-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ghostscript contained a buffer underflow in its
CCITTFax decoding filter. If a user or automated system were tricked into
opening a crafted PDF file, an attacker could cause a denial of service or
execute arbitrary code with privileges of the user invoking the program.
(CVE-2007-6725)

It was discovered that Ghostscript contained a buffer overflow in the
BaseFont writer module. If a user or automated system were tricked into
opening a crafted Postscript file, an attacker could cause a denial of
service or execute arbitrary code with privileges of the user invoking the
program. (CVE-2008-6679)

It was discovered that Ghostscript contained additional integer overflows
in its ICC color management library. If a user or automated system were
tricked into opening a crafted Postscript or PDF file, an attacker could
cause a denial of service or execute arbitrary code with privileges of the
user invoking the program. (CVE-2009-0792)

Alin Rad Pop discovered that Ghostscript contained a buffer overflow in the
jbig2dec library. If a user or automated system were tricked into opening a
crafted PDF file, an attacker could cause a denial of service or execute
arbitrary code with privileges of the user invoking the program.
(CVE-2009-0196)

USN-743-1 provided updated ghostscript and gs-gpl packages to fix two
security vulnerabilities. This update corrects the same vulnerabilities in
the gs-esp package.

Original advisory details:
 It was discovered that Ghostscript contained multiple integer overflows in
 its ICC color management library. If a user or automated system were
 tricked into opening a crafted Postscript file, an attacker could cause a
 denial of service or execute arbitrary code with privileges of the user
 invoking the program. (CVE-2009-0583)

 It was discovered that Ghostscript did not properly perform bounds
 checking in its ICC color management library. If a user or automated
 system were tricked into opening a crafted Postscript file, an attacker
 could cause a denial of service or execute arbitrary code with privileges
 of the user invoking the program. (CVE-2009-0584)");

  script_tag(name:"affected", value:"'ghostscript, gs-esp, gs-gpl' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
