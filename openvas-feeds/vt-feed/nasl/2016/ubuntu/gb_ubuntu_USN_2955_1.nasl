# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842724");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-1578", "CVE-2016-1646", "CVE-2016-1647", "CVE-2016-1649", "CVE-2016-1653", "CVE-2016-1654", "CVE-2016-1655", "CVE-2016-1659", "CVE-2016-3679");
  script_tag(name:"creation_date", value:"2016-05-06 09:59:21 +0000 (Fri, 06 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-2955-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2955-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2955-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1561450");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-2955-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free was discovered when responding synchronously to
permission requests. An attacker could potentially exploit this to cause
a denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking the program. (CVE-2016-1578)

An out-of-bounds read was discovered in V8. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash. (CVE-2016-1646)

A use-after-free was discovered in the navigation implementation in
Chromium in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking the program. (CVE-2016-1647)

A buffer overflow was discovered in ANGLE. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2016-1649)

An out-of-bounds write was discovered in V8. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash, or execute arbitrary
code with the privileges of the sandboxed renderer process.
(CVE-2016-1653)

An invalid read was discovered in the media subsystem in Chromium. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash. (CVE-2016-1654)

It was discovered that frame removal during callback execution could
trigger a use-after-free in Blink. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit this
to cause a denial of service via renderer crash, or execute arbitrary
code with the privileges of the sandboxed renderer process.
(CVE-2016-1655)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2016-1659)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could potentially
exploit these to read uninitialized memory, cause a denial of service via
renderer crash or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2016-3679)");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
