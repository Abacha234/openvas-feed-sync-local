# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842277");
  script_cve_id("CVE-2015-2721", "CVE-2015-2730");
  script_tag(name:"creation_date", value:"2015-07-10 04:09:40 +0000 (Fri, 10 Jul 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2672-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2672-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2672-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss' package(s) announced via the USN-2672-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Karthikeyan Bhargavan discovered that NSS incorrectly handled state
transitions for the TLS state machine. If a remote attacker were able to
perform a machine-in-the-middle attack, this flaw could be exploited to skip
the ServerKeyExchange message and remove the forward-secrecy property.
(CVE-2015-2721)

Watson Ladd discovered that NSS incorrectly handled Elliptical Curve
Cryptography (ECC) multiplication. A remote attacker could possibly use
this issue to spoof ECDSA signatures. (CVE-2015-2730)

As a security improvement, this update modifies NSS behaviour to reject DH
key sizes below 768 bits, preventing a possible downgrade attack.

This update also refreshes the NSS package to version 3.19.2 which includes
the latest CA certificate bundle.");

  script_tag(name:"affected", value:"'nss' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
