# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840269");
  script_cve_id("CVE-2008-3835", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4070");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-647-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-647-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-647-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-thunderbird, thunderbird' package(s) announced via the USN-647-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the same-origin check in Thunderbird could
be bypassed. If a user had JavaScript enabled and were tricked into
opening a malicious website, an attacker may be able to execute
JavaScript in the context of a different website. (CVE-2008-3835)

Several problems were discovered in the browser engine of
Thunderbird. If a user had JavaScript enabled, this could allow an
attacker to execute code with chrome privileges. (CVE-2008-4058,
CVE-2008-4059, CVE-2008-4060)

Drew Yao, David Maciejak and other Mozilla developers found several
problems in the browser engine of Thunderbird. If a user had
JavaScript enabled and were tricked into opening a malicious web
page, an attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2008-4061, CVE-2008-4062, CVE-2008-4063, CVE-2008-4064)

Dave Reed discovered a flaw in the JavaScript parsing code when
processing certain BOM characters. An attacker could exploit this
to bypass script filters and perform cross-site scripting attacks
if a user had JavaScript enabled. (CVE-2008-4065)

Gareth Heyes discovered a flaw in the HTML parser of Thunderbird. If
a user had JavaScript enabled and were tricked into opening a
malicious web page, an attacker could bypass script filtering and
perform cross-site scripting attacks. (CVE-2008-4066)

Boris Zbarsky and Georgi Guninski independently discovered flaws in
the resource: protocol. An attacker could exploit this to perform
directory traversal, read information about the system, and prompt
the user to save information in a file. (CVE-2008-4067,
CVE-2008-4068)

Georgi Guninski discovered that Thunderbird improperly handled
cancelled newsgroup messages. If a user opened a crafted newsgroup
message, an attacker could cause a buffer overrun and potentially
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2008-4070)");

  script_tag(name:"affected", value:"'mozilla-thunderbird, thunderbird' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
