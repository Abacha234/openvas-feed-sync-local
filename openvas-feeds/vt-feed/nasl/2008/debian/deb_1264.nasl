# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58119");
  script_cve_id("CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1264)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1264");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1264");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php4' package(s) announced via the DSA-1264 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in PHP, a server-side, HTML-embedded scripting language, which may lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-0906

It was discovered that an integer overflow in the str_replace() function could lead to the execution of arbitrary code.

CVE-2007-0907

It was discovered that a buffer underflow in the sapi_header_op() function could crash the PHP interpreter.

CVE-2007-0908

Stefan Esser discovered that a programming error in the wddx extension allows information disclosure.

CVE-2007-0909

It was discovered that a format string vulnerability in the odbc_result_all() functions allows the execution of arbitrary code.

CVE-2007-0910

It was discovered that super-global variables could be overwritten with session data.

CVE-2007-0988

Stefan Esser discovered that the zend_hash_init() function could be tricked into an endless loop, allowing denial of service through resource consumption until a timeout is triggered.

For the stable distribution (sarge) these problems have been fixed in version 4:4.3.10-19.

For the unstable distribution (sid) these problems have been fixed in version 6:4.4.4-9 of php4 and version 5.2.0-9 of php5.

We recommend that you upgrade your php4 packages.");

  script_tag(name:"affected", value:"'php4' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);