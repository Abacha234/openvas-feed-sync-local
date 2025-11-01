# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842619");
  script_cve_id("CVE-2016-1612", "CVE-2016-1614", "CVE-2016-1617", "CVE-2016-1618", "CVE-2016-1620", "CVE-2016-2051", "CVE-2016-2052");
  script_tag(name:"creation_date", value:"2016-01-28 05:33:14 +0000 (Thu, 28 Jan 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:33:00 +0000 (Wed, 07 Dec 2016)");

  script_name("Ubuntu: Security Advisory (USN-2877-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2877-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2877-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-2877-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A bad cast was discovered in V8. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
cause a denial of service via renderer crash or execute arbitrary code
with the privileges of the sandboxed render process. (CVE-2016-1612)

An issue was discovered when initializing the UnacceleratedImageBufferSurface
class in Blink. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to obtain sensitive
information. (CVE-2016-1614)

An issue was discovered with the CSP implementation in Blink. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to determine whether specific HSTS sites had been
visited by reading a CSP report. (CVE-2016-1617)

An issue was discovered with random number generator in Blink. An attacker
could potentially exploit this to defeat cryptographic protection
mechanisms. (CVE-2016-1618)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2016-1620)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could potentially
exploit these to read uninitialized memory, cause a denial of service via
renderer crash or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2016-2051)

Multiple security issues were discovered in Harfbuzz. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2016-2052)");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
