# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845353");
  script_cve_id("CVE-2022-1292", "CVE-2022-1343", "CVE-2022-1434", "CVE-2022-1473");
  script_tag(name:"creation_date", value:"2022-05-05 01:00:27 +0000 (Thu, 05 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-11 20:48:00 +0000 (Wed, 11 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5402-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5402-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5402-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl, openssl1.0' package(s) announced via the USN-5402-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Elison Niven discovered that OpenSSL incorrectly handled the c_rehash
script. A local attacker could possibly use this issue to execute arbitrary
commands when c_rehash is run. (CVE-2022-1292)

Raul Metsma discovered that OpenSSL incorrectly verified certain response
signing certificates. A remote attacker could possibly use this issue to
spoof certain response signing certificates. This issue only affected
Ubuntu 22.04 LTS. (CVE-2022-1343)

Tom Colley discovered that OpenSSL used the incorrect MAC key in the
RC4-MD5 ciphersuite. In non-default configurations were RC4-MD5 is enabled,
a remote attacker could possibly use this issue to modify encrypted
communications. This issue only affected Ubuntu 22.04 LTS. (CVE-2022-1434)

Aliaksei Levin discovered that OpenSSL incorrectly handled resources when
decoding certificates and keys. A remote attacker could possibly use this
issue to cause OpenSSL to consume resources, leading to a denial of
service. This issue only affected Ubuntu 22.04 LTS. (CVE-2022-1473)");

  script_tag(name:"affected", value:"'openssl, openssl1.0' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
