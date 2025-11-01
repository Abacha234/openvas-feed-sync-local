# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842011");
  script_cve_id("CVE-2014-3513", "CVE-2014-3567");
  script_tag(name:"creation_date", value:"2014-10-17 03:59:12 +0000 (Fri, 17 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2385-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2385-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2385-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-2385-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSSL incorrectly handled memory when parsing
DTLS SRTP extension data. A remote attacker could possibly use this issue
to cause OpenSSL to consume resources, resulting in a denial of service.
This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-3513)

It was discovered that OpenSSL incorrectly handled memory when verifying
the integrity of a session ticket. A remote attacker could possibly use
this issue to cause OpenSSL to consume resources, resulting in a denial of
service. (CVE-2014-3567)

In addition, this update introduces support for the TLS Fallback Signaling
Cipher Suite Value (TLS_FALLBACK_SCSV). This new feature prevents protocol
downgrade attacks when certain applications such as web browsers attempt
to reconnect using a lower protocol version for interoperability reasons.");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
