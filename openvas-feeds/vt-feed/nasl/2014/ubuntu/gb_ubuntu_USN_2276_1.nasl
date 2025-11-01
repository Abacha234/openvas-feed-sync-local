# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841890");
  script_cve_id("CVE-2014-0207", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3515", "CVE-2014-4670", "CVE-2014-4698", "CVE-2014-4721");
  script_tag(name:"creation_date", value:"2014-07-15 11:11:08 +0000 (Tue, 15 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2276-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2276-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2276-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-2276-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Francisco Alonso discovered that the PHP Fileinfo component incorrectly
handled certain CDF documents. A remote attacker could use this issue to
cause PHP to hang or crash, resulting in a denial of service.
(CVE-2014-0207, CVE-2014-3478, CVE-2014-3479, CVE-2014-3480, CVE-2014-3487)

Stefan Esser discovered that PHP incorrectly handled unserializing SPL
extension objects. An attacker could use this issue to execute arbitrary
code. (CVE-2014-3515)

It was discovered that PHP incorrectly handled certain SPL Iterators. An
attacker could use this issue to cause PHP to crash, resulting in a denial
of service. (CVE-2014-4670)

It was discovered that PHP incorrectly handled certain ArrayIterators. An
attacker could use this issue to cause PHP to crash, resulting in a denial
of service. (CVE-2014-4698)

Stefan Esser discovered that PHP incorrectly handled variable types when
calling phpinfo(). An attacker could use this issue to possibly gain access
to arbitrary memory, possibly containing sensitive information.
(CVE-2014-4721)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 13.10, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
