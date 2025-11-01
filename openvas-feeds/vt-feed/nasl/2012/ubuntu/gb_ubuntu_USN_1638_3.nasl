# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841230");
  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4203", "CVE-2012-4204", "CVE-2012-4205", "CVE-2012-5836", "CVE-2012-5842", "CVE-2012-5843");
  script_tag(name:"creation_date", value:"2012-12-04 04:15:28 +0000 (Tue, 04 Dec 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1638-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1638-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1638-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1084548");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1082446");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-1638-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1638-1 fixed vulnerabilities in Firefox. The new packages introduced
regressions in cookies handling and the User Agent string. This update fixes
the problem.

Original advisory details:

 Gary Kwong, Jesse Ruderman, Christian Holler, Bob Clary, Kyle Huey, Ed
 Morley, Chris Lord, Boris Zbarsky, Julian Seward, Bill McCloskey, and
 Andrew McCreight discovered multiple memory safety issues affecting
 Firefox. If the user were tricked into opening a specially crafted page, an
 attacker could possibly exploit these to cause a denial of service via
 application crash, or potentially execute code with the privileges of the
 user invoking Firefox. (CVE-2012-5842, CVE-2012-5843)

 Atte Kettunen discovered a buffer overflow while rendering GIF format
 images. An attacker could exploit this to possibly execute arbitrary code
 as the user invoking Firefox. (CVE-2012-4202)

 It was discovered that the evalInSandbox function's JavaScript sandbox
 context could be circumvented. An attacker could exploit this to perform a
 cross-site scripting (XSS) attack or steal a copy of a local file if the
 user has installed an add-on vulnerable to this attack. With cross-site
 scripting vulnerabilities, if a user were tricked into viewing a specially
 crafted page, a remote attacker could exploit this to modify the contents,
 or steal confidential data, within the same domain. (CVE-2012-4201)

 Jonathan Stephens discovered that combining vectors involving the setting
 of Cascading Style Sheets (CSS) properties in conjunction with SVG text
 could cause Firefox to crash. If a user were tricked into opening a
 malicious web page, an attacker could cause a denial of service via
 application crash or execute arbitrary code with the privliges of the user
 invoking the program. (CVE-2012-5836)

 It was discovered that if a javascript: URL is selected from the list of
 Firefox 'new tab' page, the script will inherit the privileges of the
 privileged 'new tab' page. This allows for the execution of locally
 installed programs if a user can be convinced to save a bookmark of a
 malicious javascript: URL. (CVE-2012-4203)

 Scott Bell discovered a memory corruption issue in the JavaScript engine.
 If a user were tricked into opening a malicious website, an attacker could
 exploit this to execute arbitrary JavaScript code within the context of
 another website or arbitrary code as the user invoking the program.
 (CVE-2012-4204)

 Gabor Krizsanits discovered that XMLHttpRequest objects created within
 sandboxes have the system principal instead of the sandbox principal. This
 can lead to cross-site request forgery (CSRF) or information theft via an
 add-on running untrusted code in a sandbox. (CVE-2012-4205)

 Peter Van der Beken discovered XrayWrapper implementation in Firefox does
 not consider the compartment during property filtering. An attacker could
 use this to bypass intended chrome-only ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
