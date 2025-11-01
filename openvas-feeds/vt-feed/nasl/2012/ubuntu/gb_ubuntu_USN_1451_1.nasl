# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841013");
  script_cve_id("CVE-2012-0884", "CVE-2012-2333");
  script_tag(name:"creation_date", value:"2012-05-25 05:11:34 +0000 (Fri, 25 May 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1451-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1451-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1451-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-1451-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ivan Nestlerode discovered that the Cryptographic Message Syntax
(CMS) and PKCS #7 implementations in OpenSSL returned early if RSA
decryption failed. This could allow an attacker to expose sensitive
information via a Million Message Attack (MMA). (CVE-2012-0884)

It was discovered that an integer underflow was possible when using
TLS 1.1, TLS 1.2, or DTLS with CBC encryption. This could allow a
remote attacker to cause a denial of service. (CVE-2012-2333)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
