# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841222");
  script_cve_id("CVE-2012-2733", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887");
  script_tag(name:"creation_date", value:"2012-11-23 06:23:31 +0000 (Fri, 23 Nov 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1637-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1637-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1637-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6' package(s) announced via the USN-1637-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Apache Tomcat HTTP NIO connector incorrectly
handled header data. A remote attacker could cause a denial of service by
sending requests with a large amount of header data. (CVE-2012-2733)

It was discovered that Apache Tomcat incorrectly handled DIGEST
authentication. A remote attacker could possibly use these flaws to perform
a replay attack and bypass authentication. (CVE-2012-5885, CVE-2012-5886,
CVE-2012-5887)");

  script_tag(name:"affected", value:"'tomcat6' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
