# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842772");
  script_cve_id("CVE-2015-8865", "CVE-2016-3078", "CVE-2016-3132", "CVE-2016-4070", "CVE-2016-4071", "CVE-2016-4072", "CVE-2016-4073", "CVE-2016-4342", "CVE-2016-4343", "CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-4544");
  script_tag(name:"creation_date", value:"2016-05-25 03:20:47 +0000 (Wed, 25 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:55:00 +0000 (Wed, 20 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-2984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2984-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2984-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5, php7.0' package(s) announced via the USN-2984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the PHP Fileinfo component incorrectly handled
certain magic files. An attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS. (CVE-2015-8865)

Hans Jerry Illikainen discovered that the PHP Zip extension incorrectly
handled certain malformed Zip archives. A remote attacker could use this
issue to cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS.
(CVE-2016-3078)

It was discovered that PHP incorrectly handled invalid indexes in the
SplDoublyLinkedList class. An attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-3132)

It was discovered that the PHP rawurlencode() function incorrectly handled
large strings. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service. This issue only affected Ubuntu
16.04 LTS. (CVE-2016-4070)

It was discovered that the PHP php_snmp_error() function incorrectly
handled string formatting. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-4071)

It was discovered that the PHP phar extension incorrectly handled certain
filenames in archives. A remote attacker could use this issue to cause PHP
to crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-4072)

It was discovered that the PHP mb_strcut() function incorrectly handled
string formatting. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-4073)

It was discovered that the PHP phar extension incorrectly handled certain
archive files. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and
Ubuntu 15.10. (CVE-2016-4342, CVE-2016-4343)

It was discovered that the PHP bcpowmod() function incorrectly handled
memory. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2016-4537, CVE-2016-4538)

It was discovered that the PHP XML parser incorrectly handled certain
malformed XML data. A remote attacker could possibly use this issue to
cause PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-4539)

It was discovered that certain PHP grapheme functions incorrectly handled
negative offsets. A remote attacker could possibly use ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php5, php7.0' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
