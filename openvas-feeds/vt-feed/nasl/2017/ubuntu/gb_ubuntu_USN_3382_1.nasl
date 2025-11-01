# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843281");
  script_cve_id("CVE-2015-8994", "CVE-2016-10397", "CVE-2017-11143", "CVE-2017-11144", "CVE-2017-11145", "CVE-2017-11147", "CVE-2017-11362", "CVE-2017-11628", "CVE-2017-9224", "CVE-2017-9226", "CVE-2017-9227", "CVE-2017-9228", "CVE-2017-9229");
  script_tag(name:"creation_date", value:"2017-08-11 05:22:54 +0000 (Fri, 11 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:34:00 +0000 (Wed, 20 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-3382-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3382-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3382-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5, php7.0' package(s) announced via the USN-3382-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the PHP opcache created keys for files it cached
based on their filepath. A local attacker could possibly use this issue in
a shared hosting environment to obtain sensitive information. This issue
only affected Ubuntu 14.04 LTS. (CVE-2015-8994)

It was discovered that the PHP URL parser incorrectly handled certain URI
components. A remote attacker could possibly use this issue to bypass
hostname-specific URL checks. This issue only affected Ubuntu 14.04 LTS.
(CVE-2016-10397)

It was discovered that PHP incorrectly handled certain boolean parameters
when unserializing data. A remote attacker could possibly use this issue to
cause PHP to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS. (CVE-2017-11143)

Sebastian Li, Wei Lei, Xie Xiaofei, and Liu Yang discovered that PHP
incorrectly handled the OpenSSL sealing function. A remote attacker could
possibly use this issue to cause PHP to crash, resulting in a denial of
service. (CVE-2017-11144)

Wei Lei and Liu Yang discovered that the PHP date extension incorrectly
handled memory. A remote attacker could possibly use this issue to disclose
sensitive information from the server. (CVE-2017-11145)

It was discovered that PHP incorrectly handled certain PHAR archives. A
remote attacker could use this issue to cause PHP to crash or disclose
sensitive information. This issue only affected Ubuntu 14.04 LTS.
(CVE-2017-11147)

It was discovered that PHP incorrectly handled locale length. A remote
attacker could possibly use this issue to cause PHP to crash, resulting in
a denial of service. (CVE-2017-11362)

Wei Lei and Liu Yang discovered that PHP incorrectly handled parsing ini
files. An attacker could possibly use this issue to cause PHP to crash,
resulting in a denial of service. (CVE-2017-11628)

It was discovered that PHP mbstring incorrectly handled certain regular
expressions. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2017-9224, CVE-2017-9226, CVE-2017-9227, CVE-2017-9228, CVE-2017-9229)");

  script_tag(name:"affected", value:"'php5, php7.0' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
