# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57689");
  script_cve_id("CVE-2006-4310", "CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5748");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1225)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1225");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1225");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla-firefox' package(s) announced via the DSA-1225 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update covers packages for the little endian MIPS architecture missing in the original advisory. For reference please find below the original advisory text:

Several security related problems have been discovered in Mozilla and derived products such as Mozilla Firefox. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2006-4310

Tomas Kempinsky discovered that malformed FTP server responses could lead to denial of service.

CVE-2006-5462

Ulrich Kuhn discovered that the correction for a cryptographic flaw in the handling of PKCS-1 certificates was incomplete, which allows the forgery of certificates.

CVE-2006-5463

shutdown discovered that modification of JavaScript objects during execution could lead to the execution of arbitrary JavaScript bytecode.

CVE-2006-5464

Jesse Ruderman and Martijn Wargers discovered several crashes in the layout engine, which might also allow execution of arbitrary code.

CVE-2006-5748

Igor Bukanov and Jesse Ruderman discovered several crashes in the JavaScript engine, which might allow execution of arbitrary code.

This update also addresses several crashes, which could be triggered by malicious websites and fixes a regression introduced in the previous Mozilla update.

For the stable distribution (sarge) these problems have been fixed in version 1.0.4-2sarge13.

For the unstable distribution (sid) these problems have been fixed in the current iceweasel package 2.0+dfsg-1.

We recommend that you upgrade your mozilla-firefox package.");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);