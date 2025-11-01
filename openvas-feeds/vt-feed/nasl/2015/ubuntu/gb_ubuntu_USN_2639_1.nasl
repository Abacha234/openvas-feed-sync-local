# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842242");
  script_cve_id("CVE-2014-8176", "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792");
  script_tag(name:"creation_date", value:"2015-06-12 04:09:14 +0000 (Fri, 12 Jun 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:29:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-2639-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2639-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2639-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-2639-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Praveen Kariyanahalli, Ivan Fratric and Felix Groebert discovered that
OpenSSL incorrectly handled memory when buffering DTLS data. A remote
attacker could use this issue to cause OpenSSL to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2014-8176)

Joseph Barr-Pixton discovered that OpenSSL incorrectly handled malformed
ECParameters structures. A remote attacker could use this issue to cause
OpenSSL to hang, resulting in a denial of service. (CVE-2015-1788)

Robert Swiecki and Hanno Bock discovered that OpenSSL incorrectly handled
certain ASN1_TIME strings. A remote attacker could use this issue to cause
OpenSSL to crash, resulting in a denial of service. (CVE-2015-1789)

Michal Zalewski discovered that OpenSSL incorrectly handled missing content
when parsing ASN.1-encoded PKCS#7 blobs. A remote attacker could use this
issue to cause OpenSSL to crash, resulting in a denial of service.
(CVE-2015-1790)

Emilia Kasper discovered that OpenSSL incorrectly handled NewSessionTicket
when being used by a multi-threaded client. A remote attacker could use
this issue to cause OpenSSL to crash, resulting in a denial of service.
(CVE-2015-1791)

Johannes Bauer discovered that OpenSSL incorrectly handled verifying
signedData messages using the CMS code. A remote attacker could use this
issue to cause OpenSSL to hang, resulting in a denial of service.
(CVE-2015-1792)

As a security improvement, this update also modifies OpenSSL behaviour to
reject DH key sizes below 768 bits, preventing a possible downgrade
attack.");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
