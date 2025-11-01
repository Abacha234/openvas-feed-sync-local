# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844547");
  script_cve_id("CVE-2017-6318", "CVE-2020-12861", "CVE-2020-12862", "CVE-2020-12863", "CVE-2020-12864", "CVE-2020-12865", "CVE-2020-12866", "CVE-2020-12867");
  script_tag(name:"creation_date", value:"2020-08-25 03:00:47 +0000 (Tue, 25 Aug 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-4470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4470-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4470-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sane-backends' package(s) announced via the USN-4470-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kritphong Mongkhonvanit discovered that sane-backends incorrectly handled
certain packets. A remote attacker could possibly use this issue to obtain
sensitive memory information. This issue only affected Ubuntu 16.04 LTS.
(CVE-2017-6318)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to execute
arbitrary code. This issue only applied to Ubuntu 18.04 LTS and Ubuntu
20.04 LTS. (CVE-2020-12861)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to obtain
sensitive information. (CVE-2020-12862, CVE-2020-12863)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to obtain
sensitive information. This issue only applied to Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-12864)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to execute
arbitrary code. (CVE-2020-12865)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to cause a
denial of service. This issue only applied to Ubuntu 18.04 LTS and Ubuntu
20.04 LTS. (CVE-2020-12866)

It was discovered that sane-backends incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to cause a
denial of service. (CVE-2020-12867)");

  script_tag(name:"affected", value:"'sane-backends' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
