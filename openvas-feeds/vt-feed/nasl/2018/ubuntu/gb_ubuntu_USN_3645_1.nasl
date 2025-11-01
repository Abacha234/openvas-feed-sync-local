# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843521");
  script_cve_id("CVE-2018-5150", "CVE-2018-5151", "CVE-2018-5152", "CVE-2018-5153", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5157", "CVE-2018-5158", "CVE-2018-5159", "CVE-2018-5160", "CVE-2018-5163", "CVE-2018-5164", "CVE-2018-5166", "CVE-2018-5167", "CVE-2018-5168", "CVE-2018-5169", "CVE-2018-5172", "CVE-2018-5173", "CVE-2018-5175", "CVE-2018-5176", "CVE-2018-5177", "CVE-2018-5180", "CVE-2018-5181", "CVE-2018-5182");
  script_tag(name:"creation_date", value:"2018-05-12 03:48:49 +0000 (Sat, 12 May 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-11 16:06:00 +0000 (Mon, 11 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-3645-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3645-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3645-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3645-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, bypass same-origin restrictions, conduct cross-site scripting (XSS)
attacks, install lightweight themes without user interaction, spoof the
filename in the downloads panel, or execute arbitrary code.
(CVE-2018-5150, CVE-2018-5151, CVE-2018-5153, CVE-2018-5154,
CVE-2018-5155, CVE-2018-5157, CVE-2018-5158, CVE-2018-5159, CVE-2018-5160,
CVE-2018-5163, CVE-2018-5164, CVE-2018-5168, CVE-2018-5173, CVE-2018-5175,
CVE-2018-5177, CVE-2018-5180)

Multiple security issues were discovered with WebExtensions. If a user
were tricked in to installing a specially crafted extension, an attacker
could potentially exploit these to obtain sensitive information, or bypass
security restrictions. (CVE-2018-5152, CVE-2018-5166)

It was discovered that the web console and JavaScript debugger incorrectly
linkified chrome: and javascript URLs. If a user were tricked in to
clicking a specially crafted link, an attacker could potentially exploit
this to conduct cross-site scripting (XSS) attacks. (CVE-2018-5167)

It was discovered that dragging and dropping link text on to the home
button could set the home page to include chrome pages. If a user were
tricked in to dragging and dropping a specially crafted link on to the
home button, an attacker could potentially exploit this bypass security
restrictions. (CVE-2018-5169)

It was discovered that the Live Bookmarks page and PDF viewer would run
script pasted from the clipboard. If a user were tricked in to copying and
pasting specially crafted text, an attacker could potentially exploit this
to conduct cross-site scripting (XSS) attacks. (CVE-2018-5172)

It was discovered that the JSON viewer incorrectly linkified javascript:
URLs. If a user were tricked in to clicking on a specially crafted link,
an attacker could potentially exploit this to obtain sensitive
information. (CVE-2018-5176)

It was discovered that dragging a file: URL on to a tab that is running in
a different process would cause the file to open in that process. If a
user were tricked in to dragging a file: URL, an attacker could
potentially exploit this to bypass intended security policies.
(CVE-2018-5181)

It was discovered that dragging text that is a file: URL on to the
addressbar would open the specified file. If a user were tricked in to
dragging specially crafted text on to the addressbar, an attacker could
potentially exploit this to bypass intended security policies.
(CVE-2018-5182)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
