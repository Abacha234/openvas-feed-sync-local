# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845074");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-33193", "CVE-2021-34798", "CVE-2021-36160", "CVE-2021-39275", "CVE-2021-40438");
  script_tag(name:"creation_date", value:"2021-09-28 01:00:26 +0000 (Tue, 28 Sep 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-30 15:20:00 +0000 (Thu, 30 Sep 2021)");

  script_name("Ubuntu: Security Advisory (USN-5090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5090-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5090-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-5090-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"James Kettle discovered that the Apache HTTP Server HTTP/2 module
incorrectly handled certain crafted methods. A remote attacker could
possibly use this issue to perform request splitting or cache poisoning
attacks. (CVE-2021-33193)

It was discovered that the Apache HTTP Server incorrectly handled certain
malformed requests. A remote attacker could possibly use this issue to
cause the server to crash, resulting in a denial of service.
(CVE-2021-34798)

Li Zhi Xin discovered that the Apache mod_proxy_uwsgi module incorrectly
handled certain request uri-paths. A remote attacker could possibly use
this issue to cause the server to crash, resulting in a denial of service.
This issue only affected Ubuntu 20.04 LTS and Ubuntu 21.04.
(CVE-2021-36160)

It was discovered that the Apache HTTP Server incorrectly handled escaping
quotes. If the server was configured with third-party modules, a remote
attacker could use this issue to cause the server to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2021-39275)

It was discovered that the Apache mod_proxy module incorrectly handled
certain request uri-paths. A remote attacker could possibly use this issue
to cause the server to forward requests to arbitrary origin servers.
(CVE-2021-40438)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
