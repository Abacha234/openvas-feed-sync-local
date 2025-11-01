# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844979");
  script_cve_id("CVE-2018-16869", "CVE-2021-3580");
  script_tag(name:"creation_date", value:"2021-06-18 03:00:35 +0000 (Fri, 18 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-13 17:51:00 +0000 (Fri, 13 Aug 2021)");

  script_name("Ubuntu: Security Advisory (USN-4990-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4990-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4990-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nettle' package(s) announced via the USN-4990-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Nettle incorrectly handled RSA decryption. A remote
attacker could possibly use this issue to cause Nettle to crash, resulting
in a denial of service. (CVE-2021-3580)

It was discovered that Nettle incorrectly handled certain padding oracles.
A remote attacker could possibly use this issue to perform a variant of the
Bleichenbacher attack. This issue only affected Ubuntu 18.04 LTS.
(CVE-2018-16869)");

  script_tag(name:"affected", value:"'nettle' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
