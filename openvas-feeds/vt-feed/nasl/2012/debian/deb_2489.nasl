# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71466");
  script_cve_id("CVE-2012-1937", "CVE-2012-1940", "CVE-2012-1947");
  script_tag(name:"creation_date", value:"2012-08-10 07:01:59 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2489)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2489");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2489");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceape' package(s) announced via the DSA-2489 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Iceape internet suite, an unbranded version of Seamonkey.

CVE-2012-1937

Mozilla developers discovered several memory corruption bugs, which may lead to the execution of arbitrary code.

CVE-2012-1940

Abhishek Arya discovered a use-after-free problem when working with column layout with absolute positioning in a container that changes size, which may lead to the execution of arbitrary code.

CVE-2012-1947

Abhishek Arya discovered a heap buffer overflow in utf16 to latin1 character set conversion, allowing to execute arbitrary code.

For the stable distribution (squeeze), this problem has been fixed in version 2.0.11-13.

For the testing distribution (wheezy) and unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your iceape packages.");

  script_tag(name:"affected", value:"'iceape' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);