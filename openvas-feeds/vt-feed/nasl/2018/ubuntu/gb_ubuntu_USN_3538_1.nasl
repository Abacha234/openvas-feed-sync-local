# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843425");
  script_cve_id("CVE-2016-10009", "CVE-2016-10010", "CVE-2016-10011", "CVE-2016-10012", "CVE-2017-15906");
  script_tag(name:"creation_date", value:"2018-01-23 06:38:02 +0000 (Tue, 23 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-11 10:29:00 +0000 (Tue, 11 Sep 2018)");

  script_name("Ubuntu: Security Advisory (USN-3538-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3538-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3538-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the USN-3538-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that OpenSSH incorrectly loaded PKCS#11 modules from
untrusted directories. A remote attacker could possibly use this issue to
execute arbitrary PKCS#11 modules. This issue only affected Ubuntu 14.04
LTS and Ubuntu 16.04 LTS. (CVE-2016-10009)

Jann Horn discovered that OpenSSH incorrectly handled permissions on
Unix-domain sockets when privilege separation is disabled. A local attacker
could possibly use this issue to gain privileges. This issue only affected
Ubuntu 16.04 LTS. (CVE-2016-10010)

Jann Horn discovered that OpenSSH incorrectly handled certain buffer memory
operations. A local attacker could possibly use this issue to obtain
sensitive information. This issue only affected Ubuntu 14.04 LTS and Ubuntu
16.04 LTS. (CVE-2016-10011)

Guido Vranken discovered that OpenSSH incorrectly handled certain shared
memory manager operations. A local attacker could possibly use issue to
gain privileges. This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04
LTS. This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-10012)

Michal Zalewski discovered that OpenSSH incorrectly prevented write
operations in readonly mode. A remote attacker could possibly use this
issue to create zero-length files, leading to a denial of service.
(CVE-2017-15906)");

  script_tag(name:"affected", value:"'openssh' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
