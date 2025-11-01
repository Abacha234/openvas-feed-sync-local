# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844450");
  script_cve_id("CVE-2019-1547", "CVE-2019-1549", "CVE-2019-1551", "CVE-2019-1563");
  script_tag(name:"creation_date", value:"2020-05-29 03:00:35 +0000 (Fri, 29 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4376-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4376-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4376-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-4376-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cesar Pereida Garcia, Sohaib ul Hassan, Nicola Tuveri, Iaroslav Gridin,
Alejandro Cabrera Aldaya, and Billy Brumley discovered that OpenSSL
incorrectly handled ECDSA signatures. An attacker could possibly use this
issue to perform a timing side-channel attack and recover private ECDSA
keys. (CVE-2019-1547)

Matt Caswell discovered that OpenSSL incorrectly handled the random number
generator (RNG). This may result in applications that use the fork() system
call sharing the same RNG state between the parent and the child, contrary
to expectations. This issue only affected Ubuntu 18.04 LTS and Ubuntu
19.10. (CVE-2019-1549)

Guido Vranken discovered that OpenSSL incorrectly performed the x86_64
Montgomery squaring procedure. While unlikely, a remote attacker could
possibly use this issue to recover private keys. (CVE-2019-1551)

Bernd Edlinger discovered that OpenSSL incorrectly handled certain
decryption functions. In certain scenarios, a remote attacker could
possibly use this issue to perform a padding oracle attack and decrypt
traffic. (CVE-2019-1563)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
