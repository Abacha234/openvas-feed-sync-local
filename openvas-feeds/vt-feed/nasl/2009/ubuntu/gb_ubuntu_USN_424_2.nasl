# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840188");
  script_cve_id("CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-424-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-424-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-424-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/87481");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-424-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-424-1 fixed vulnerabilities in PHP. However, some upstream changes
were not included, which caused errors in the stream filters. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple buffer overflows have been discovered in various PHP modules.
 If a PHP application processes untrusted data with functions of the
 session or zip module, or various string functions, a remote attacker
 could exploit this to execute arbitrary code with the privileges of
 the web server. (CVE-2007-0906)

 The sapi_header_op() function had a buffer underflow that could be
 exploited to crash the PHP interpreter. (CVE-2007-0907)

 The wddx unserialization handler did not correctly check for some
 buffer boundaries and had an uninitialized variable. By unserializing
 untrusted data, this could be exploited to expose memory regions that
 were not meant to be accessible. Depending on the PHP application this
 could lead to disclosure of potentially sensitive information.
 (CVE-2007-0908)

 On 64 bit systems (the amd64 and sparc platforms), various print
 functions and the odbc_result_all() were susceptible to a format
 string vulnerability. A remote attacker could exploit this to execute
 arbitrary code with the privileges of the web server. (CVE-2007-0909)

 Under certain circumstances it was possible to overwrite superglobal
 variables (like the HTTP GET/POST arrays) with crafted session data.
 (CVE-2007-0910)

 When unserializing untrusted data on 64-bit platforms the
 zend_hash_init() function could be forced to enter an infinite loop,
 consuming CPU resources, for a limited length of time, until the
 script timeout alarm aborts the script. (CVE-2007-0988)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 5.10, Ubuntu 6.06, Ubuntu 6.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
