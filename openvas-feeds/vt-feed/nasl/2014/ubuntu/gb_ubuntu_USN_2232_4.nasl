# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841933");
  script_cve_id("CVE-2014-0195", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470");
  script_tag(name:"creation_date", value:"2014-08-19 03:58:49 +0000 (Tue, 19 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2232-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2232-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2232-4");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1356843");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-2232-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2232-1 fixed vulnerabilities in OpenSSL. One of the patch backports for
Ubuntu 10.04 LTS caused a regression for certain applications. This update
fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Juri Aedla discovered that OpenSSL incorrectly handled invalid DTLS
 fragments. A remote attacker could use this issue to cause OpenSSL to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code. This issue only affected Ubuntu 12.04 LTS, Ubuntu 13.10, and
 Ubuntu 14.04 LTS. (CVE-2014-0195)

 Imre Rad discovered that OpenSSL incorrectly handled DTLS recursions. A
 remote attacker could use this issue to cause OpenSSL to crash, resulting
 in a denial of service. (CVE-2014-0221)

 KIKUCHI Masashi discovered that OpenSSL incorrectly handled certain
 handshakes. A remote attacker could use this flaw to perform a
 machine-in-the-middle attack and possibly decrypt and modify traffic.
 (CVE-2014-0224)

 Felix Grobert and Ivan Fratric discovered that OpenSSL incorrectly handled
 anonymous ECDH ciphersuites. A remote attacker could use this issue to
 cause OpenSSL to crash, resulting in a denial of service. This issue only
 affected Ubuntu 12.04 LTS, Ubuntu 13.10, and Ubuntu 14.04 LTS.
 (CVE-2014-3470)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
