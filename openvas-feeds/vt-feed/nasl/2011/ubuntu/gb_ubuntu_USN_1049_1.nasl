# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840604");
  script_cve_id("CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059", "CVE-2011-0061", "CVE-2011-0062");
  script_tag(name:"creation_date", value:"2011-03-07 05:45:55 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1049-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1049-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1049-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-3.0, firefox-3.5, xulrunner-1.9.2' package(s) announced via the USN-1049-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jesse Ruderman, Igor Bukanov, Olli Pettay, Gary Kwong, Jeff Walden, Henry
Sivonen, Martijn Wargers, David Baron and Marcia Knous discovered several
memory issues in the browser engine. An attacker could exploit these to
crash the browser or possibly run arbitrary code as the user invoking the
program. (CVE-2011-0053, CVE-2011-0062)

Zach Hoffman discovered that a recursive call to eval() wrapped in a
try/catch statement places the browser into a inconsistent state. An
attacker could exploit this to force a user to accept any dialog.
(CVE-2011-0051)

It was discovered that memory was used after being freed in a method used
by JSON.stringify. An attacker could exploit this to crash the browser or
possibly run arbitrary code as the user invoking the program.
(CVE-2011-0055)

Christian Holler discovered multiple buffer overflows in the JavaScript
engine. An attacker could exploit these to crash the browser or possibly
run arbitrary code as the user invoking the program. (CVE-2011-0054,
CVE-2011-0056)

Daniel Kozlowski discovered that a JavaScript Worker kept a reference to
memory after it was freed. An attacker could exploit this to crash the
browser or possibly run arbitrary code as the user invoking the program.
(CVE-2011-0057)

Alex Miller discovered a buffer overflow in the browser rendering engine.
An attacker could exploit this to crash the browser or possibly run
arbitrary code as the user invoking the program. (CVE-2011-0058)

Roberto Suggi Liverani discovered a possible issue with unsafe JavaScript
execution in chrome documents. A malicious extension could exploit this to
execute arbitrary code with chrome privlieges. (CVE-2010-1585)

Jordi Chancel discovered a buffer overflow in the JPEG decoding engine. An
attacker could exploit this to crash the browser or possibly run arbitrary
code as the user invoking the program. (CVE-2011-0061)

Peleus Uhley discovered a CSRF vulnerability in the plugin code related to
307 redirects. This could allow custom headers to be forwarded across
origins. (CVE-2011-0059)");

  script_tag(name:"affected", value:"'firefox, firefox-3.0, firefox-3.5, xulrunner-1.9.2' package(s) on Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
