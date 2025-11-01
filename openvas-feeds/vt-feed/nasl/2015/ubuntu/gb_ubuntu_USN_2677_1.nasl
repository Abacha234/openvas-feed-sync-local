# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842401");
  script_cve_id("CVE-2015-1270", "CVE-2015-1272", "CVE-2015-1276", "CVE-2015-1277", "CVE-2015-1280", "CVE-2015-1281", "CVE-2015-1283", "CVE-2015-1284", "CVE-2015-1285", "CVE-2015-1287", "CVE-2015-1289", "CVE-2015-1329", "CVE-2015-5605");
  script_tag(name:"creation_date", value:"2015-08-05 03:08:52 +0000 (Wed, 05 Aug 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-2677-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2677-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2677-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1466208");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-2677-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An uninitialized value issue was discovered in ICU. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service. (CVE-2015-1270)

A use-after-free was discovered in the GPU process implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1272)

A use-after-free was discovered in the IndexedDB implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1276)

A use-after-free was discovered in the accessibility implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1277)

A memory corruption issue was discovered in Skia. If a user were tricked
in to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or execute
arbitrary code with the privileges of the sandboxed render process.
(CVE-2015-1280)

It was discovered that Blink did not properly determine the V8 context of
a microtask in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
bypass Content Security Policy (CSP) restrictions. (CVE-2015-1281)

Multiple integer overflows were discovered in Expat. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
the program. (CVE-2015-1283)

It was discovered that Blink did not enforce a page's maximum number of
frames in some circumstances, resulting in a use-after-free. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer crash,
or execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2015-1284)

It was discovered that the XSS auditor in Blink did not properly choose a
truncation point. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to obtain sensitive
information. (CVE-2015-1285)

An issue was discovered in the CSS implementation in Blink. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
