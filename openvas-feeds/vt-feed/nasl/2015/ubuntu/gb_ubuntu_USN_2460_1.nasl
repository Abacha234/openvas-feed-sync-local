# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842050");
  script_cve_id("CVE-2014-8634", "CVE-2014-8638", "CVE-2014-8639");
  script_tag(name:"creation_date", value:"2015-01-23 11:58:10 +0000 (Fri, 23 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2460-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2460-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2460-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-2460-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Holler and Patrick McManus discovered multiple memory safety
issues in Thunderbird. If a user were tricked in to opening a specially
crafted message with scripting enabled, an attacker could potentially
exploit these to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2014-8634)

Muneaki Nishimura discovered that requests from navigator.sendBeacon()
lack an origin header. If a user were tricked in to opening a specially
crafted message with scripting enabled, an attacker could potentially
exploit this to conduct cross-site request forgery (XSRF) attacks.
(CVE-2014-8638)

Xiaofeng Zheng discovered that a web proxy returning a 407 response
could inject cookies in to the originally requested domain. If a user
connected to a malicious web proxy, an attacker could potentially exploit
this to conduct session-fixation attacks. (CVE-2014-8639)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
