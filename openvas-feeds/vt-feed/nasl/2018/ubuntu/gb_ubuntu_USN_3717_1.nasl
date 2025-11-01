# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843594");
  script_cve_id("CVE-2015-3218", "CVE-2015-3255", "CVE-2015-4625", "CVE-2018-1116");
  script_tag(name:"creation_date", value:"2018-07-17 03:51:28 +0000 (Tue, 17 Jul 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-05 16:05:00 +0000 (Tue, 05 May 2020)");

  script_name("Ubuntu: Security Advisory (USN-3717-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3717-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3717-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'policykit-1' package(s) announced via the USN-3717-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered that PolicyKit incorrectly handled certain invalid
object paths. A local attacker could possibly use this issue to cause
PolicyKit to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS. (CVE-2015-3218)

It was discovered that PolicyKit incorrectly handled certain duplicate
action IDs. A local attacker could use this issue to cause PolicyKit to
crash, resulting in a denial of service, or possibly escalate privileges.
This issue only affected Ubuntu 14.04 LTS. (CVE-2015-3255)

Tavis Ormandy discovered that PolicyKit incorrectly handled duplicate
cookie values. A local attacker could use this issue to cause PolicyKit to
crash, resulting in a denial of service, or possibly escalate privileges.
This issue only affected Ubuntu 14.04 LTS. (CVE-2015-4625)

Matthias Gerstner discovered that PolicyKit incorrectly checked users. A
local attacker could possibly use this issue to cause authentication
dialogs to show up for other users, leading to a denial of service or an
information leak. (CVE-2018-1116)");

  script_tag(name:"affected", value:"'policykit-1' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
