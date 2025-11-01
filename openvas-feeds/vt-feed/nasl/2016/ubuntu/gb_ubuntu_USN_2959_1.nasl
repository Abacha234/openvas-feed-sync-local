# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842729");
  script_cve_id("CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109");
  script_tag(name:"creation_date", value:"2016-05-04 03:19:55 +0000 (Wed, 04 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-2959-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2959-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2959-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-2959-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Huzaifa Sidhpurwala, Hanno Bock, and David Benjamin discovered that OpenSSL
incorrectly handled memory when decoding ASN.1 structures. A remote
attacker could use this issue to cause OpenSSL to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2016-2108)

Juraj Somorovsky discovered that OpenSSL incorrectly performed padding when
the connection uses the AES CBC cipher and the server supports AES-NI. A
remote attacker could possibly use this issue to perform a padding oracle
attack and decrypt traffic. (CVE-2016-2107)

Guido Vranken discovered that OpenSSL incorrectly handled large amounts of
input data to the EVP_EncodeUpdate() function. A remote attacker could use
this issue to cause OpenSSL to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-2105)

Guido Vranken discovered that OpenSSL incorrectly handled large amounts of
input data to the EVP_EncryptUpdate() function. A remote attacker could use
this issue to cause OpenSSL to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-2106)

Brian Carpenter discovered that OpenSSL incorrectly handled memory when
ASN.1 data is read from a BIO. A remote attacker could possibly use this
issue to cause memory consumption, resulting in a denial of service.
(CVE-2016-2109)

As a security improvement, this update also modifies OpenSSL behaviour to
reject DH key sizes below 1024 bits, preventing a possible downgrade
attack.");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
