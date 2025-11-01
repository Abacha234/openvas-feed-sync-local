# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842136");
  script_cve_id("CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293");
  script_tag(name:"creation_date", value:"2015-03-20 05:56:31 +0000 (Fri, 20 Mar 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2537-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2537-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2537-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-2537-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSSL incorrectly handled malformed EC private key
files. A remote attacker could possibly use this issue to cause OpenSSL to
crash, resulting in a denial of service, or execute arbitrary code.
(CVE-2015-0209)

Stephen Henson discovered that OpenSSL incorrectly handled comparing ASN.1
boolean types. A remote attacker could possibly use this issue to cause
OpenSSL to crash, resulting in a denial of service. (CVE-2015-0286)

Emilia Kasper discovered that OpenSSL incorrectly handled ASN.1 structure
reuse. A remote attacker could possibly use this issue to cause OpenSSL to
crash, resulting in a denial of service, or execute arbitrary code.
(CVE-2015-0287)

Brian Carpenter discovered that OpenSSL incorrectly handled invalid
certificate keys. A remote attacker could possibly use this issue to cause
OpenSSL to crash, resulting in a denial of service. (CVE-2015-0288)

Michal Zalewski discovered that OpenSSL incorrectly handled missing outer
ContentInfo when parsing PKCS#7 structures. A remote attacker could
possibly use this issue to cause OpenSSL to crash, resulting in a denial of
service, or execute arbitrary code. (CVE-2015-0289)

Robert Dugal and David Ramos discovered that OpenSSL incorrectly handled
decoding Base64 encoded data. A remote attacker could possibly use this
issue to cause OpenSSL to crash, resulting in a denial of service, or
execute arbitrary code. (CVE-2015-0292)

Sean Burford and Emilia Kasper discovered that OpenSSL incorrectly handled
specially crafted SSLv2 CLIENT-MASTER-KEY messages. A remote attacker could
possibly use this issue to cause OpenSSL to crash, resulting in a denial of
service. (CVE-2015-0293)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
