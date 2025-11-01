# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842740");
  script_cve_id("CVE-2015-8325", "CVE-2016-1907", "CVE-2016-1908", "CVE-2016-3115");
  script_tag(name:"creation_date", value:"2016-05-10 03:21:23 +0000 (Tue, 10 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-18 13:51:00 +0000 (Thu, 18 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-2966-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2966-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2966-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the USN-2966-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Shayan Sadigh discovered that OpenSSH incorrectly handled environment files
when the UseLogin feature is enabled. A local attacker could use this issue
to gain privileges. (CVE-2015-8325)

Ben Hawkes discovered that OpenSSH incorrectly handled certain network
traffic. A remote attacker could possibly use this issue to cause OpenSSH
to crash, resulting in a denial of service. This issue only applied to
Ubuntu 15.10. (CVE-2016-1907)

Thomas Hoger discovered that OpenSSH incorrectly handled untrusted X11
forwarding when the SECURITY extension is disabled. A connection configured
as being untrusted could get switched to trusted in certain scenarios,
contrary to expectations. (CVE-2016-1908)

It was discovered that OpenSSH incorrectly handled certain X11 forwarding
data. A remote authenticated attacker could possibly use this issue to
bypass certain intended command restrictions. (CVE-2016-3115)");

  script_tag(name:"affected", value:"'openssh' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
