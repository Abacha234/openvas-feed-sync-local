# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840027");
  script_cve_id("CVE-2007-3089", "CVE-2007-3285", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-490-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-490-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-490-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-490-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various flaws were discovered in the layout and JavaScript engines. By
tricking a user into opening a malicious web page, an attacker could
execute arbitrary code with the user's privileges. (CVE-2007-3734,
CVE-2007-3735)

Flaws were discovered in the JavaScript methods addEventListener and
setTimeout which could be used to inject script into another site in
violation of the browser's same-origin policy. A malicious web site
could exploit this to modify the contents, or steal confidential data
(such as passwords), of other web pages. (CVE-2007-3736)

Ronen Zilberman and Michal Zalewski discovered timing attacks in the
JavaScript engine's use of about:blank frames. A malicious web site
could exploit this to modify the contents, or steal confidential data
(such as passwords), of other web pages. (CVE-2007-3089)

A flaw was discovered in the JavaScript event handling code. By tricking
a user into opening a malicious web page, an attacker could execute
arbitrary code with the user's privileges. (CVE-2007-3737)

Ronald van den Heetkamp discovered that filename URLs including an encoded
null byte could confuse the extension matching code. By tricking a user
into opening a malicious web page, an attacker could execute arbitrary
helper programs. (CVE-2007-3285)

Michal Zalewski discovered flaws in the same-origin handling of cached
'wyciwyg://' documents. A malicious web site could exploit this to
modify the contents, or steal confidential data (such as passwords),
of other web pages. (CVE-2007-3656)

Various flaws were discovered in the XPCNativeWrapper method. By tricking
a user into opening a malicious web page, an attacker could execute
arbitrary code with the user's privileges. (CVE-2007-3738).");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
