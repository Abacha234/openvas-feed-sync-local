# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843848");
  script_cve_id("CVE-2018-0734", "CVE-2018-0735", "CVE-2018-5407");
  script_tag(name:"creation_date", value:"2018-12-07 06:39:41 +0000 (Fri, 07 Dec 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3840-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3840-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3840-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl, openssl1.0' package(s) announced via the USN-3840-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Samuel Weiser discovered that OpenSSL incorrectly handled DSA signing. An
attacker could possibly use this issue to perform a timing side-channel
attack and recover private DSA keys. (CVE-2018-0734)

Samuel Weiser discovered that OpenSSL incorrectly handled ECDSA signing. An
attacker could possibly use this issue to perform a timing side-channel
attack and recover private ECDSA keys. This issue only affected Ubuntu
18.04 LTS and Ubuntu 18.10. (CVE-2018-0735)

Billy Bob Brumley, Cesar Pereida Garcia, Sohaib ul Hassan, Nicola Tuveri,
and Alejandro Cabrera Aldaya discovered that Simultaneous Multithreading
(SMT) architectures are vulnerable to side-channel leakage. This issue is
known as 'PortSmash'. An attacker could possibly use this issue to perform
a timing side-channel attack and recover private keys. (CVE-2018-5407)");

  script_tag(name:"affected", value:"'openssl, openssl1.0' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
