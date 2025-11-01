# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842775");
  script_cve_id("CVE-2013-2207", "CVE-2014-8121", "CVE-2014-9761", "CVE-2015-1781", "CVE-2015-5277", "CVE-2015-8776", "CVE-2015-8777", "CVE-2015-8778", "CVE-2015-8779", "CVE-2016-2856");
  script_tag(name:"creation_date", value:"2016-05-27 03:20:47 +0000 (Fri, 27 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2985-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2985-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2985-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1585614");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc, glibc' package(s) announced via the USN-2985-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2985-1 fixed vulnerabilities in the GNU C Library. The fix for
CVE-2014-9761 introduced a regression which affected applications that
use the libm library but were not fully restarted after the upgrade.
This update removes the fix for CVE-2014-9761 and a future update
will be provided to address this issue.

We apologize for the inconvenience.

Original advisory details:

 Martin Carpenter discovered that pt_chown in the GNU C Library did not
 properly check permissions for tty files. A local attacker could use this
 to gain administrative privileges or expose sensitive information.
 (CVE-2013-2207, CVE-2016-2856)

 Robin Hack discovered that the Name Service Switch (NSS) implementation in
 the GNU C Library did not properly manage its file descriptors. An attacker
 could use this to cause a denial of service (infinite loop).
 (CVE-2014-8121)

 Joseph Myers discovered that the GNU C Library did not properly handle long
 arguments to functions returning a representation of Not a Number (NaN). An
 attacker could use this to cause a denial of service (stack exhaustion
 leading to an application crash) or possibly execute arbitrary code.
 (CVE-2014-9761)

 Arjun Shankar discovered that in certain situations the nss_dns code in the
 GNU C Library did not properly account buffer sizes when passed an
 unaligned buffer. An attacker could use this to cause a denial of service
 or possibly execute arbitrary code. (CVE-2015-1781)

 Sumit Bose and Lukas Slebodnik discovered that the Name Service
 Switch (NSS) implementation in the GNU C Library did not handle long
 lines in the files databases correctly. A local attacker could use
 this to cause a denial of service (application crash) or possibly
 execute arbitrary code. (CVE-2015-5277)

 Adam Nielsen discovered that the strftime function in the GNU C Library did
 not properly handle out-of-range argument data. An attacker could use this
 to cause a denial of service (application crash) or possibly expose
 sensitive information. (CVE-2015-8776)

 Hector Marco and Ismael Ripoll discovered that the GNU C Library allowed
 the pointer-guarding protection mechanism to be disabled by honoring the
 LD_POINTER_GUARD environment variable across privilege boundaries. A local
 attacker could use this to exploit an existing vulnerability more easily.
 (CVE-2015-8777)

 Szabolcs Nagy discovered that the hcreate functions in the GNU C Library
 did not properly check its size argument, leading to an integer overflow.
 An attacker could use to cause a denial of service (application crash) or
 possibly execute arbitrary code. (CVE-2015-8778)

 Maksymilian Arciemowicz discovered a stack-based buffer overflow in the
 catopen function in the GNU C Library when handling long catalog names. An
 attacker could use this to cause a denial of service (application crash) or
 possibly execute arbitrary code. (CVE-2015-8779)

 Florian Weimer discovered that ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'eglibc, glibc' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
