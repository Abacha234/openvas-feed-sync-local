# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703169");
  script_cve_id("CVE-2012-3406", "CVE-2013-7424", "CVE-2014-4043", "CVE-2014-9402", "CVE-2015-1472", "CVE-2015-1473");
  script_tag(name:"creation_date", value:"2015-02-22 23:00:00 +0000 (Sun, 22 Feb 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3169)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3169");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3169");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'eglibc' package(s) announced via the DSA-3169 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in eglibc, Debian's version of the GNU C library:

CVE-2012-3406

The vfprintf function in stdio-common/vfprintf.c in GNU C Library (aka glibc) 2.5, 2.12, and probably other versions does not properly restrict the use of the alloca function when allocating the SPECS array, which allows context-dependent attackers to bypass the FORTIFY_SOURCE format-string protection mechanism and cause a denial of service (crash) or possibly execute arbitrary code via a crafted format string using positional parameters and a large number of format specifiers, a different vulnerability than CVE-2012-3404 and CVE-2012-3405.

CVE-2013-7424

An invalid free flaw was found in glibc's getaddrinfo() function when used with the AI_IDN flag. A remote attacker able to make an application call this function could use this flaw to execute arbitrary code with the permissions of the user running the application. Note that this flaw only affected applications using glibc compiled with libidn support.

CVE-2014-4043

The posix_spawn_file_actions_addopen function in glibc before 2.20 does not copy its path argument in accordance with the POSIX specification, which allows context-dependent attackers to trigger use-after-free vulnerabilities.

CVE-2014-9402

The getnetbyname function in glibc 2.21 or earlier will enter an infinite loop if the DNS backend is activated in the system Name Service Switch configuration, and the DNS resolver receives a positive answer while processing the network name.

CVE-2015-1472 / CVE-2015-1473 Under certain conditions wscanf can allocate too little memory for the to-be-scanned arguments and overflow the allocated buffer. The incorrect use of '__libc_use_alloca (newsize)' caused a different (and weaker) policy to be enforced which could allow a denial of service attack.

For the stable distribution (wheezy), these issues are fixed in version 2.13-38+deb7u8 of the eglibc package.

For the unstable distribution (sid), all the above issues are fixed in version 2.19-15 of the glibc package.

We recommend that you upgrade your eglibc packages.");

  script_tag(name:"affected", value:"'eglibc' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);