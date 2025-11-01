# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842262");
  script_cve_id("CVE-2014-0227", "CVE-2014-0230", "CVE-2014-7810");
  script_tag(name:"creation_date", value:"2015-06-26 04:25:12 +0000 (Fri, 26 Jun 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2655-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2655-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2655-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6' package(s) announced via the USN-2655-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly handled data with malformed
chunked transfer coding. A remote attacker could possibly use this issue to
conduct HTTP request smuggling attacks, or cause Tomcat to consume
resources, resulting in a denial of service. (CVE-2014-0227)

It was discovered that Tomcat incorrectly handled HTTP responses occurring
before the entire request body was finished being read. A remote attacker
could possibly use this issue to cause a limited denial of service.
(CVE-2014-0230)

It was discovered that the Tomcat Expression Language (EL) implementation
incorrectly handled accessible interfaces implemented by inaccessible
classes. An attacker could possibly use this issue to bypass a
SecurityManager protection mechanism. (CVE-2014-7810)");

  script_tag(name:"affected", value:"'tomcat6' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
