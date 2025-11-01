# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842123");
  script_cve_id("CVE-2013-5704", "CVE-2014-3581", "CVE-2014-3583", "CVE-2014-8109", "CVE-2015-0228");
  script_tag(name:"creation_date", value:"2015-03-11 05:40:48 +0000 (Wed, 11 Mar 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2523-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2523-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2523-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-2523-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Martin Holst Swende discovered that the mod_headers module allowed HTTP
trailers to replace HTTP headers during request processing. A remote
attacker could possibly use this issue to bypass RequestHeaders directives.
(CVE-2013-5704)

Mark Montague discovered that the mod_cache module incorrectly handled
empty HTTP Content-Type headers. A remote attacker could use this issue to
cause the server to stop responding, leading to a denial of service. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2014-3581)

Teguh P. Alko discovered that the mod_proxy_fcgi module incorrectly
handled long response headers. A remote attacker could use this issue to
cause the server to stop responding, leading to a denial of service. This
issue only affected Ubuntu 14.10. (CVE-2014-3583)

It was discovered that the mod_lua module incorrectly handled different
arguments within different contexts. A remote attacker could possibly use
this issue to bypass intended access restrictions. This issue only affected
Ubuntu 14.10. (CVE-2014-8109)

Guido Vranken discovered that the mod_lua module incorrectly handled a
specially crafted websocket PING in certain circumstances. A remote
attacker could possibly use this issue to cause the server to stop
responding, leading to a denial of service. This issue only affected
Ubuntu 14.10. (CVE-2015-0228)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
