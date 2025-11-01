# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843108");
  script_cve_id("CVE-2015-8982", "CVE-2015-8983", "CVE-2015-8984", "CVE-2016-1234", "CVE-2016-3706", "CVE-2016-4429", "CVE-2016-5417", "CVE-2016-6323");
  script_tag(name:"creation_date", value:"2017-03-25 04:50:32 +0000 (Sat, 25 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3239-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3239-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3239-3");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/bugs/1674776");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc' package(s) announced via the USN-3239-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3239-1 fixed vulnerabilities in the GNU C Library. Unfortunately,
the fix for CVE-2016-3706 introduced a regression that in some
circumstances prevented IPv6 addresses from resolving. This update
reverts the change in Ubuntu 12.04 LTS. We apologize for the error.

Original advisory details:

 It was discovered that the GNU C Library incorrectly handled the
 strxfrm() function. An attacker could use this issue to cause a denial
 of service or possibly execute arbitrary code. This issue only affected
 Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8982)

 It was discovered that an integer overflow existed in the
 _IO_wstr_overflow() function of the GNU C Library. An attacker could
 use this to cause a denial of service or possibly execute arbitrary
 code. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04
 LTS. (CVE-2015-8983)

 It was discovered that the fnmatch() function in the GNU C Library
 did not properly handle certain malformed patterns. An attacker could
 use this to cause a denial of service. This issue only affected Ubuntu
 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8984)

 Alexander Cherepanov discovered a stack-based buffer overflow in the
 glob implementation of the GNU C Library. An attacker could use this
 to specially craft a directory layout and cause a denial of service.
 (CVE-2016-1234)

 Michael Petlan discovered an unbounded stack allocation in the
 getaddrinfo() function of the GNU C Library. An attacker could use
 this to cause a denial of service. (CVE-2016-3706)

 Aldy Hernandez discovered an unbounded stack allocation in the sunrpc
 implementation in the GNU C Library. An attacker could use this to
 cause a denial of service. (CVE-2016-4429)

 Tim Ruehsen discovered that the getaddrinfo() implementation in the
 GNU C Library did not properly track memory allocations. An attacker
 could use this to cause a denial of service. This issue only affected
 Ubuntu 16.04 LTS. (CVE-2016-5417)

 Andreas Schwab discovered that the GNU C Library on ARM 32-bit
 platforms did not properly set up execution contexts. An attacker
 could use this to cause a denial of service. (CVE-2016-6323)");

  script_tag(name:"affected", value:"'eglibc' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
