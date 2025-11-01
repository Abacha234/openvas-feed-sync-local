# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841774");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0076", "CVE-2014-0160");
  script_tag(name:"creation_date", value:"2014-04-08 06:37:01 +0000 (Tue, 08 Apr 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:29:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-2165-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2165-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2165-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-2165-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Neel Mehta discovered that OpenSSL incorrectly handled memory in the TLS
heartbeat extension. An attacker could use this issue to obtain up to 64k
of memory contents from the client or server, possibly leading to the
disclosure of private keys and other sensitive information. (CVE-2014-0160)

Yuval Yarom and Naomi Benger discovered that OpenSSL incorrectly handled
timing during swap operations in the Montgomery ladder implementation. An
attacker could use this issue to perform side-channel attacks and possibly
recover ECDSA nonces. (CVE-2014-0076)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
