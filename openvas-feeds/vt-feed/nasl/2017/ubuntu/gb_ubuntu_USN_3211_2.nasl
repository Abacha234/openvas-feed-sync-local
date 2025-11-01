# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843071");
  script_cve_id("CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160", "CVE-2016-10161", "CVE-2016-10162", "CVE-2016-7479", "CVE-2016-9137", "CVE-2016-9935", "CVE-2016-9936", "CVE-2017-5340");
  script_tag(name:"creation_date", value:"2017-03-03 04:50:08 +0000 (Fri, 03 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3211-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3211-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3211-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1668017");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.0' package(s) announced via the USN-3211-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3211-1 fixed vulnerabilities in PHP by updating to the new 7.0.15
upstream release. PHP 7.0.15 introduced a regression when using MySQL with
large blobs. This update fixes the problem with a backported fix.

Original advisory details:

 It was discovered that PHP incorrectly handled certain invalid objects when
 unserializing data. A remote attacker could use this issue to cause PHP to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code. (CVE-2016-7479)

 It was discovered that PHP incorrectly handled certain invalid objects when
 unserializing data. A remote attacker could use this issue to cause PHP to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code. (CVE-2016-9137)

 It was discovered that PHP incorrectly handled unserializing certain
 wddxPacket XML documents. A remote attacker could use this issue to cause
 PHP to crash, resulting in a denial of service, or possibly execute
 arbitrary code. (CVE-2016-9935)

 It was discovered that PHP incorrectly handled certain invalid objects when
 unserializing data. A remote attacker could use this issue to cause PHP to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code. (CVE-2016-9936)

 It was discovered that PHP incorrectly handled certain EXIF data. A remote
 attacker could use this issue to cause PHP to crash, resulting in a denial
 of service. (CVE-2016-10158)

 It was discovered that PHP incorrectly handled certain PHAR archives. A
 remote attacker could use this issue to cause PHP to crash or consume
 resources, resulting in a denial of service. (CVE-2016-10159)

 It was discovered that PHP incorrectly handled certain PHAR archives. A
 remote attacker could use this issue to cause PHP to crash, resulting in a
 denial of service, or possibly execute arbitrary code. (CVE-2016-10160)

 It was discovered that PHP incorrectly handled certain invalid objects when
 unserializing data. A remote attacker could use this issue to cause PHP to
 crash, resulting in a denial of service. (CVE-2016-10161)

 It was discovered that PHP incorrectly handled unserializing certain
 wddxPacket XML documents. A remote attacker could use this issue to cause
 PHP to crash, resulting in a denial of service. (CVE-2016-10162)

 It was discovered that PHP incorrectly handled certain invalid objects when
 unserializing data. A remote attacker could use this issue to cause PHP to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code. (CVE-2017-5340)");

  script_tag(name:"affected", value:"'php7.0' package(s) on Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
