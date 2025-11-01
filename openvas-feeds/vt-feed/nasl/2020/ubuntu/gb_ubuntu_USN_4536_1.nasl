# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844611");
  script_cve_id("CVE-2017-15736", "CVE-2019-11071", "CVE-2019-16391", "CVE-2019-16392", "CVE-2019-16393", "CVE-2019-16394", "CVE-2019-19830");
  script_tag(name:"creation_date", value:"2020-09-25 03:00:25 +0000 (Fri, 25 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 18:15:00 +0000 (Mon, 28 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-4536-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4536-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4536-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spip' package(s) announced via the USN-4536-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Youssouf Boulouiz discovered that SPIP incorrectly handled login error
messages. A remote attacker could potentially exploit this to conduct
cross-site scripting (XSS) attacks. (CVE-2019-16392)

Gilles Vincent discovered that SPIP incorrectly handled password reset
requests. A remote attacker could possibly use this issue to cause SPIP to
enumerate registered users. (CVE-2019-16394)

Guillaume Fahrner discovered that SPIP did not properly sanitize input. A
remote authenticated attacker could possibly use this issue to execute
arbitrary code on the host server. (CVE-2019-11071)

Sylvain Lefevre discovered that SPIP incorrectly handled user
authorization. A remote attacker could possibly use this issue to modify
and publish content and modify the database. (CVE-2019-16391)

It was discovered that SPIP did not properly sanitize input. A remote
attacker could, through cross-site scripting (XSS) and PHP injection,
exploit this to inject arbitrary web script or HTML. (CVE-2017-15736)

Alexis Zucca discovered that SPIP incorrectly handled the media plugin. A
remote authenticated attacker could possibly use this issue to write to
the database. (CVE-2019-19830)

Christophe Laffont discovered that SPIP incorrectly handled redirect URLs.
An attacker could use this issue to cause SPIP to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2019-16393)");

  script_tag(name:"affected", value:"'spip' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
