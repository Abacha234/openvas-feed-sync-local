# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842677");
  script_cve_id("CVE-2014-6270", "CVE-2016-2571");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:34 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)");

  script_name("Ubuntu: Security Advisory (USN-2921-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2921-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2921-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3' package(s) announced via the USN-2921-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sebastian Krahmer discovered that Squid incorrectly handled certain SNMP
requests. If SNMP is enabled, a remote attacker could use this issue to
cause Squid to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2014-6270)

Alex Rousskov discovered that Squid incorrectly handled certain malformed
responses. A remote attacker could possibly use this issue to cause Squid
to crash, resulting in a denial of service. (CVE-2016-2571)");

  script_tag(name:"affected", value:"'squid3' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
