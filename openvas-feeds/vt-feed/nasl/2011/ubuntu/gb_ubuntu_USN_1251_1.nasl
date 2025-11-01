# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840801");
  script_cve_id("CVE-2011-3004", "CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650");
  script_tag(name:"creation_date", value:"2011-11-11 04:25:39 +0000 (Fri, 11 Nov 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1251-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1251-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1251-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, xulrunner-1.9.2' package(s) announced via the USN-1251-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that CVE-2011-3004, which addressed possible privilege
escalation in addons, also affected Firefox 3.6. An attacker could
potentially exploit Firefox when an add-on was installed that used
loadSubscript in vulnerable ways. (CVE-2011-3647)

Yosuke Hasegawa discovered that the Mozilla browser engine mishandled
invalid sequences in the Shift-JIS encoding. A malicious website could
possibly use this flaw this to steal data or inject malicious scripts into
web content. (CVE-2011-3648)

Marc Schoenefeld discovered that using Firebug to profile a JavaScript file
with many functions would cause Firefox to crash. An attacker might be able
to exploit this without using the debugging APIs which would potentially
allow an attacker to remotely crash the browser. (CVE-2011-3650)");

  script_tag(name:"affected", value:"'firefox, xulrunner-1.9.2' package(s) on Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
