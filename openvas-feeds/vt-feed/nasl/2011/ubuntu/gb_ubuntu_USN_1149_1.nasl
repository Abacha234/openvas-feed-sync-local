# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840684");
  script_cve_id("CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2376", "CVE-2011-2377");
  script_tag(name:"creation_date", value:"2011-06-24 14:46:35 +0000 (Fri, 24 Jun 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1149-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1149-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1149-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, xulrunner-1.9.2' package(s) announced via the USN-1149-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple memory vulnerabilities were discovered in the browser rendering
engine. An attacker could use these to possibly execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2011-2364, CVE-2011-2365,
CVE-2011-2374, CVE-2011-2376)

Martin Barbella discovered that under certain conditions, viewing a XUL
document while JavaScript was disabled caused deleted memory to be
accessed. An attacker could potentially use this to crash Firefox or
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2011-2373)

Jordi Chancel discovered a vulnerability on multipart/x-mixed-replace
images due to memory corruption. An attacker could potentially use this to
crash Firefox or execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2011-2377)

Chris Rohlf and Yan Ivnitskiy discovered an integer overflow vulnerability
in JavaScript Arrays. An attacker could potentially use this to execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2011-2371)

Multiple use-after-free vulnerabilities were discovered. An attacker could
potentially use these to execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2011-0083, CVE-2011-0085, CVE-2011-2363)

David Chan discovered that cookies did not honor same-origin conventions.
This could potentially lead to cookie data being leaked to a third party.
(CVE-2011-2362)");

  script_tag(name:"affected", value:"'firefox, xulrunner-1.9.2' package(s) on Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
