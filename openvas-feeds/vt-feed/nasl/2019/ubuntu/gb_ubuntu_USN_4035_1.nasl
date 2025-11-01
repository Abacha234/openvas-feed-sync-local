# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844068");
  script_cve_id("CVE-2018-14662", "CVE-2018-16846", "CVE-2018-16889", "CVE-2019-3821");
  script_tag(name:"creation_date", value:"2019-06-26 02:00:59 +0000 (Wed, 26 Jun 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-13 16:15:00 +0000 (Fri, 13 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-4035-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4035-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4035-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the USN-4035-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ceph incorrectly handled read only permissions. An
authenticated attacker could use this issue to obtain dm-crypt encryption
keys. This issue only affected Ubuntu 16.04 LTS. (CVE-2018-14662)

It was discovered that Ceph incorrectly handled certain OMAPs holding
bucket indices. An authenticated attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 16.04 LTS.
(CVE-2018-16846)

It was discovered that Ceph incorrectly sanitized certain debug logs. A
local attacker could possibly use this issue to obtain encryption key
information. This issue was only addressed in Ubuntu 18.10 and Ubuntu
19.04. (CVE-2018-16889)

It was discovered that Ceph incorrectly handled certain civetweb requests.
A remote attacker could possibly use this issue to consume resources,
leading to a denial of service. This issue only affected Ubuntu 18.10 and
Ubuntu 19.04. (CVE-2019-3821)");

  script_tag(name:"affected", value:"'ceph' package(s) on Ubuntu 16.04, Ubuntu 18.10, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
