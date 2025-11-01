# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843407");
  script_cve_id("CVE-2017-5647", "CVE-2017-5648", "CVE-2017-5664", "CVE-2017-7674");
  script_tag(name:"creation_date", value:"2018-01-09 09:10:39 +0000 (Tue, 09 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-20 21:15:00 +0000 (Mon, 20 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-3519-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3519-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3519-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat7, tomcat8' package(s) announced via the USN-3519-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly handled certain pipelined
requests when sendfile was used. A remote attacker could use this issue to
obtain wrong responses possibly containing sensitive information.
(CVE-2017-5647)

It was discovered that Tomcat incorrectly used the appropriate facade
object. A malicious application could possibly use this to bypass Security
Manager restrictions. (CVE-2017-5648)

It was discovered that Tomcat incorrectly handled error pages. A remote
attacker could possibly use this issue to replace or remove the custom
error page. (CVE-2017-5664)

It was discovered that Tomcat incorrectly handled the CORS filter. A remote
attacker could possibly use this issue to perform cache poisoning.
(CVE-2017-7674)");

  script_tag(name:"affected", value:"'tomcat7, tomcat8' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
