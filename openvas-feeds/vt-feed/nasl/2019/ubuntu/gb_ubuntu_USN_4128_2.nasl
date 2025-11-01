# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844181");
  script_cve_id("CVE-2019-0199", "CVE-2019-0221", "CVE-2019-10072");
  script_tag(name:"creation_date", value:"2019-09-19 02:03:05 +0000 (Thu, 19 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4128-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4128-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4128-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat9' package(s) announced via the USN-4128-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Tomcat 9 SSI printenv command echoed user
provided data without escaping it. An attacker could possibly use this
issue to perform an XSS attack. (CVE-2019-0221)

It was discovered that Tomcat 9 did not address HTTP/2 connection window
exhaustion on write while addressing CVE-2019-0199. An attacker could
possibly use this issue to cause a denial of service. (CVE-2019-10072)");

  script_tag(name:"affected", value:"'tomcat9' package(s) on Ubuntu 18.04, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
