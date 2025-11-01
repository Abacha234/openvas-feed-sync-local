# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61370");
  script_cve_id("CVE-2008-2376", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");
  script_tag(name:"creation_date", value:"2008-08-15 13:52:52 +0000 (Fri, 15 Aug 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1618)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1618");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1618");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.9' package(s) announced via the DSA-1618 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the interpreter for the Ruby language, which may lead to denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-2662

Drew Yao discovered that multiple integer overflows in the string processing code may lead to denial of service and potentially the execution of arbitrary code.

CVE-2008-2663

Drew Yao discovered that multiple integer overflows in the string processing code may lead to denial of service and potentially the execution of arbitrary code.

CVE-2008-2664

Drew Yao discovered that a programming error in the string processing code may lead to denial of service and potentially the execution of arbitrary code.

CVE-2008-2725

Drew Yao discovered that an integer overflow in the array handling code may lead to denial of service and potentially the execution of arbitrary code.

CVE-2008-2726

Drew Yao discovered that an integer overflow in the array handling code may lead to denial of service and potentially the execution of arbitrary code.

CVE-2008-2376

It was discovered that an integer overflow in the array handling code may lead to denial of service and potentially the execution of arbitrary code.

For the stable distribution (etch), these problems have been fixed in version 1.9.0+20060609-1etch2.

For the unstable distribution (sid), these problems have been fixed in version 1.9.0.2-2.

We recommend that you upgrade your ruby1.9 packages.");

  script_tag(name:"affected", value:"'ruby1.9' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);