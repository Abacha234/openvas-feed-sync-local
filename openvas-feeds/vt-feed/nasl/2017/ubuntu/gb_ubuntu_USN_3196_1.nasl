# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843051");
  script_cve_id("CVE-2014-9912", "CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160", "CVE-2016-10161", "CVE-2016-7478", "CVE-2016-7479", "CVE-2016-9137", "CVE-2016-9934", "CVE-2016-9935");
  script_tag(name:"creation_date", value:"2017-02-15 04:49:31 +0000 (Wed, 15 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-04 01:29:00 +0000 (Fri, 04 May 2018)");

  script_name("Ubuntu: Security Advisory (USN-3196-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3196-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3196-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-3196-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP incorrectly handled certain arguments to the
locale_get_display_name function. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2014-9912)

It was discovered that PHP incorrectly handled certain invalid objects when
unserializing data. A remote attacker could use this issue to cause PHP to
hang, resulting in a denial of service. (CVE-2016-7478)

It was discovered that PHP incorrectly handled certain invalid objects when
unserializing data. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2016-7479)

It was discovered that PHP incorrectly handled certain invalid objects when
unserializing data. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only applied to Ubuntu 14.04 LTS. (CVE-2016-9137)

It was discovered that PHP incorrectly handled unserializing certain
wddxPacket XML documents. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service. (CVE-2016-9934)

It was discovered that PHP incorrectly handled unserializing certain
wddxPacket XML documents. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-9935)

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
crash, resulting in a denial of service. (CVE-2016-10161)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
