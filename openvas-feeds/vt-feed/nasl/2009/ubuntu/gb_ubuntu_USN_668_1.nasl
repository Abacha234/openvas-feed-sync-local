# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840253");
  script_cve_id("CVE-2008-5012", "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5024");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-668-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-668-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-668-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-thunderbird, thunderbird' package(s) announced via the USN-668-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Georgi Guninski, Michal Zalewsk and Chris Evans discovered that the same-origin
check in Thunderbird could be bypassed. If a user were tricked into opening a
malicious website, an attacker could obtain private information from data
stored in the images, or discover information about software on the user's
computer. (CVE-2008-5012)

Jesse Ruderman discovered that Thunderbird did not properly guard locks on
non-native objects. If a user had JavaScript enabled and were tricked into
opening malicious web content, an attacker could cause a browser crash and
possibly execute arbitrary code with user privileges. (CVE-2008-5014)

Several problems were discovered in the browser, layout and JavaScript engines.
If a user had JavaScript enabled, these problems could allow an attacker to
crash Thunderbird and possibly execute arbitrary code with user privileges.
(CVE-2008-5016, CVE-2008-5017, CVE-2008-5018)

A flaw was discovered in Thunderbird's DOM constructing code. If a user were
tricked into opening a malicious website while having JavaScript enabled, an
attacker could cause the browser to crash and potentially execute arbitrary
code with user privileges. (CVE-2008-5021)

It was discovered that the same-origin check in Thunderbird could be bypassed.
If a user had JavaScript enabled and were tricked into opening malicious web
content, an attacker could execute JavaScript in the context of a different
website. (CVE-2008-5022)

Chris Evans discovered that Thunderbird did not properly parse E4X documents,
leading to quote characters in the namespace not being properly escaped.
(CVE-2008-5024)

Boris Zbarsky discovered that Thunderbird did not properly process comments in
forwarded in-line messages. If a user had JavaScript enabled and opened a
malicious email, an attacker may be able to obtain information about the
recipient.");

  script_tag(name:"affected", value:"'mozilla-thunderbird, thunderbird' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
