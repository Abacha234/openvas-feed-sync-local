# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842892");
  script_cve_id("CVE-2016-1240");
  script_tag(name:"creation_date", value:"2016-09-20 03:41:58 +0000 (Tue, 20 Sep 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-3081-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3081-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3081-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1609819");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6, tomcat7, tomcat8' package(s) announced via the USN-3081-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dawid Golunski discovered that the Tomcat init script incorrectly handled
creating log files. A remote attacker could possibly use this issue to
obtain root privileges. (CVE-2016-1240)

This update also reverts a change in behaviour introduced in USN-3024-1 by
setting mapperContextRootRedirectEnabled to True by default.");

  script_tag(name:"affected", value:"'tomcat6, tomcat7, tomcat8' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
