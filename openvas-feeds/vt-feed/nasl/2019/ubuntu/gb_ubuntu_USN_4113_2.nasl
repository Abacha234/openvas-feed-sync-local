# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844179");
  script_cve_id("CVE-2019-0197", "CVE-2019-10081", "CVE-2019-10082", "CVE-2019-10092", "CVE-2019-10097", "CVE-2019-10098", "CVE-2019-9517");
  script_tag(name:"creation_date", value:"2019-09-18 02:01:06 +0000 (Wed, 18 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4113-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4113-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4113-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1842701");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-4113-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4113-1 fixed vulnerabilities in the Apache HTTP server.
Unfortunately, that update introduced a regression when proxying
balancer manager connections in some configurations. This update
fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Stefan Eissing discovered that the HTTP/2 implementation in Apache
 did not properly handle upgrade requests from HTTP/1.1 to HTTP/2 in
 some situations. A remote attacker could use this to cause a denial
 of service (daemon crash). This issue only affected Ubuntu 18.04 LTS
 and Ubuntu 19.04. (CVE-2019-0197)

 Craig Young discovered that a memory overwrite error existed in
 Apache when performing HTTP/2 very early pushes in some situations. A
 remote attacker could use this to cause a denial of service (daemon
 crash). This issue only affected Ubuntu 18.04 LTS and Ubuntu 19.04.
 (CVE-2019-10081)

 Craig Young discovered that a read-after-free error existed in the
 HTTP/2 implementation in Apache during connection shutdown. A remote
 attacker could use this to possibly cause a denial of service (daemon
 crash) or possibly expose sensitive information. This issue only
 affected Ubuntu 18.04 LTS and Ubuntu 19.04. (CVE-2019-10082)

 Matei Badanoiu discovered that the mod_proxy component of
 Apache did not properly filter URLs when reporting errors in some
 configurations. A remote attacker could possibly use this issue to
 conduct cross-site scripting (XSS) attacks. (CVE-2019-10092)

 Daniel McCarney discovered that mod_remoteip component of Apache
 contained a stack buffer overflow when parsing headers from a trusted
 intermediary proxy in some situations. A remote attacker controlling a
 trusted proxy could use this to cause a denial of service or possibly
 execute arbitrary code. This issue only affected Ubuntu 19.04.
 (CVE-2019-10097)

 Yukitsugu Sasaki discovered that the mod_rewrite component in Apache
 was vulnerable to open redirects in some situations. A remote attacker
 could use this to possibly expose sensitive information or bypass
 intended restrictions. (CVE-2019-10098)

 Jonathan Looney discovered that the HTTP/2 implementation in Apache did
 not properly limit the amount of buffering for client connections in
 some situations. A remote attacker could use this to cause a denial
 of service (unresponsive daemon). This issue only affected Ubuntu
 18.04 LTS and Ubuntu 19.04. (CVE-2019-9517)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
