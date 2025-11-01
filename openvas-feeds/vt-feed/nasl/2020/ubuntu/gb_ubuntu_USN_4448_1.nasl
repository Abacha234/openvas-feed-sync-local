# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844527");
  script_cve_id("CVE-2020-13935", "CVE-2020-1935", "CVE-2020-9484");
  script_tag(name:"creation_date", value:"2020-08-05 03:00:33 +0000 (Wed, 05 Aug 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4448-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4448-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4448-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat8' package(s) announced via the USN-4448-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly validated the payload length in
a WebSocket frame. A remote attacker could possibly use this issue to cause
Tomcat to hang, resulting in a denial of service. (CVE-2020-13935)

It was discovered that Tomcat incorrectly handled HTTP header parsing. In
certain environments where Tomcat is located behind a reverse proxy, a
remote attacker could possibly use this issue to perform HTTP Request
Smuggling. (CVE-2020-1935)

It was discovered that Tomcat incorrectly handled certain uncommon
PersistenceManager with FileStore configurations. A remote attacker could
possibly use this issue to execute arbitrary code. (CVE-2020-9484)");

  script_tag(name:"affected", value:"'tomcat8' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
