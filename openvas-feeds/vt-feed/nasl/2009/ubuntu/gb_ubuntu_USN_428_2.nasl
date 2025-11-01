# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840114");
  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-1092");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-428-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-428-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-428-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/88990");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-428-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-428-1 fixed vulnerabilities in Firefox 1.5. However, changes to
library paths caused applications depending on libnss3 to fail to start
up. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Several flaws have been found that could be used to perform Cross-site
 scripting attacks. A malicious web site could exploit these to modify
 the contents or steal confidential data (such as passwords) from other
 opened web pages. (CVE-2006-6077, CVE-2007-0780, CVE-2007-0800,
 CVE-2007-0981, CVE-2007-0995, CVE-2007-0996)

 The SSLv2 protocol support in the NSS library did not sufficiently
 check the validity of public keys presented with a SSL certificate. A
 malicious SSL web site using SSLv2 could potentially exploit this to
 execute arbitrary code with the user's privileges. (CVE-2007-0008)

 The SSLv2 protocol support in the NSS library did not sufficiently
 verify the validity of client master keys presented in an SSL client
 certificate. A remote attacker could exploit this to execute arbitrary
 code in a server application that uses the NSS library.
 (CVE-2007-0009)

 Various flaws have been reported that could allow an attacker to
 execute arbitrary code with user privileges by tricking the user into
 opening a malicious web page. (CVE-2007-0775, CVE-2007-0776,
 CVE-2007-0777, CVE-2007-1092)

 Two web pages could collide in the disk cache with the result that
 depending on order loaded the end of the longer document could be
 appended to the shorter when the shorter one was reloaded from the
 cache. It is possible a determined hacker could construct a targeted
 attack to steal some sensitive data from a particular web page. The
 potential victim would have to be already logged into the targeted
 service (or be fooled into doing so) and then visit the malicious
 site. (CVE-2007-0778)

 David Eckel reported that browser UI elements--such as the host name
 and security indicators--could be spoofed by using custom cursor
 images and a specially crafted style sheet. (CVE-2007-0779)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 6.06.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
