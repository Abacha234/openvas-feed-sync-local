# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842771");
  script_cve_id("CVE-2016-1660", "CVE-2016-1661", "CVE-2016-1663", "CVE-2016-1665", "CVE-2016-1666", "CVE-2016-1667", "CVE-2016-1668", "CVE-2016-1669", "CVE-2016-1670");
  script_tag(name:"creation_date", value:"2016-05-19 03:21:28 +0000 (Thu, 19 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:18:00 +0000 (Tue, 16 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-2960-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2960-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2960-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-2960-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out of bounds write was discovered in Blink. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or execute
arbitrary code. (CVE-2016-1660)

It was discovered that Blink assumes that a frame which passes same-origin
checks is local in some cases. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
cause a denial of service via renderer crash, or execute arbitrary code.
(CVE-2016-1661)

A use-after-free was discovered in the V8 bindings in Blink. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer crash,
or execute arbitrary code. (CVE-2016-1663)

It was discovered that the JSGenericLowering class in V8 mishandles
comparison operators. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to obtain
sensitive information. (CVE-2016-1665)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code.
(CVE-2016-1666)

It was discovered that the TreeScope::adoptIfNeeded function in Blink
does not prevent script execution during node-adoption operations. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to bypass same origin restrictions.
(CVE-2016-1667)

It was discovered that the forEachForBinding in the V8 bindings in Blink
uses an improper creation context. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
bypass same origin restrictions. (CVE-2016-1668)

A buffer overflow was discovered in V8. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash, or execute arbitrary
code. (CVE-2016-1669)

A race condition was discovered in ResourceDispatcherHostImpl in Chromium.
An attacker could potentially exploit this to make arbitrary HTTP
requests. (CVE-2016-1670)");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
