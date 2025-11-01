# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844977");
  script_cve_id("CVE-2020-26558", "CVE-2020-27153", "CVE-2021-3588");
  script_tag(name:"creation_date", value:"2021-06-17 03:00:28 +0000 (Thu, 17 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-09 19:15:00 +0000 (Mon, 09 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-4989-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4989-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4989-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez' package(s) announced via the USN-4989-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that BlueZ incorrectly checked certain permissions when
pairing. A local attacker could possibly use this issue to impersonate
devices. (CVE-2020-26558)

Jay LV discovered that BlueZ incorrectly handled redundant disconnect MGMT
events. A local attacker could use this issue to cause BlueZ to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-27153)

Ziming Zhang discovered that BlueZ incorrectly handled certain array
indexes. A local attacker could use this issue to cause BlueZ to crash,
resulting in a denial of service, or possibly obtain sensitive information.
This issue only affected Ubuntu 20.04 LTS and Ubuntu 20.10. (CVE-2021-3588)");

  script_tag(name:"affected", value:"'bluez' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
