# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64323");
  script_cve_id("CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1386", "CVE-2009-1387");
  script_tag(name:"creation_date", value:"2009-06-29 22:29:55 +0000 (Mon, 29 Jun 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-792-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-792-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-792-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-792-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSSL did not limit the number of DTLS records it
would buffer when they arrived with a future epoch. A remote attacker could
cause a denial of service via memory resource consumption by sending a
large number of crafted requests. (CVE-2009-1377)

It was discovered that OpenSSL did not properly free memory when processing
DTLS fragments. A remote attacker could cause a denial of service via
memory resource consumption by sending a large number of crafted requests.
(CVE-2009-1378)

It was discovered that OpenSSL did not properly handle certain server
certificates when processing DTLS packets. A remote DTLS server could cause
a denial of service by sending a message containing a specially crafted
server certificate. (CVE-2009-1379)

It was discovered that OpenSSL did not properly handle a DTLS
ChangeCipherSpec packet when it occurred before ClientHello. A remote
attacker could cause a denial of service by sending a specially crafted
request. (CVE-2009-1386)

It was discovered that OpenSSL did not properly handle out of sequence
DTLS handshake messages. A remote attacker could cause a denial of service
by sending a specially crafted request. (CVE-2009-1387)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
