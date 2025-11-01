# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58120");
  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6505");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1265)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1265");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1265");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla' package(s) announced via the DSA-1265 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in Mozilla and derived products. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2006-6497

Several vulnerabilities in the layout engine allow remote attackers to cause a denial of service and possibly permit them to execute arbitrary code. [MFSA 2006-68]

CVE-2006-6498

Several vulnerabilities in the JavaScript engine allow remote attackers to cause a denial of service and possibly permit them to execute arbitrary code. [MFSA 2006-68]

CVE-2006-6499

A bug in the js_dtoa function allows remote attackers to cause a denial of service. [MFSA 2006-68]

CVE-2006-6501

shutdown discovered a vulnerability that allows remote attackers to gain privileges and install malicious code via the watch JavaScript function. [MFSA 2006-70]

CVE-2006-6502

Steven Michaud discovered a programming bug that allows remote attackers to cause a denial of service. [MFSA 2006-71]

CVE-2006-6503

moz_bug_r_a4 reported that the src attribute of an IMG element could be used to inject JavaScript code. [MFSA 2006-72]

CVE-2006-6505

Georgi Guninski discovered several heap-based buffer overflows that allow remote attackers to execute arbitrary code. [MFSA 2006-74]

For the stable distribution (sarge) these problems have been fixed in version 1.7.8-1sarge10.

For the unstable distribution (sid) these problems have been fixed in version 1.0.7-1 of iceape.

We recommend that you upgrade your Mozilla and Iceape packages.");

  script_tag(name:"affected", value:"'mozilla' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);