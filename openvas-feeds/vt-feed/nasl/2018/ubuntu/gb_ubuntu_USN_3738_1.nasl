# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843615");
  script_cve_id("CVE-2018-10858", "CVE-2018-10918", "CVE-2018-10919", "CVE-2018-1139");
  script_tag(name:"creation_date", value:"2018-08-15 04:19:51 +0000 (Wed, 15 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-26 08:15:00 +0000 (Wed, 26 Jun 2019)");

  script_name("Ubuntu: Security Advisory (USN-3738-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3738-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3738-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-3738-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Svyatoslav Phirsov discovered that the Samba libsmbclient library
incorrectly handled extra long filenames. A malicious server could use this
issue to cause Samba to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2018-10858)

Volker Mauel discovered that Samba incorrectly handled database output.
When used as an Active Directory Domain Controller, a remote authenticated
attacker could use this issue to cause Samba to crash, resulting in a
denial of service. This issue only affected Ubuntu 18.04 LTS.
(CVE-2018-10918)

Phillip Kuhrt discovered that the Samba LDAP server incorrectly handled
certain confidential attribute values. A remote authenticated attacker
could possibly use this issue to obtain certain sensitive information.
(CVE-2018-10919)

Vivek Das discovered that Samba incorrectly handled NTLMv1 being explicitly
disabled on the server. A remote user could possibly be authenticated using
NTLMv1, contrary to expectations. This issue only affected Ubuntu 18.04
LTS. (CVE-2018-1139)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
