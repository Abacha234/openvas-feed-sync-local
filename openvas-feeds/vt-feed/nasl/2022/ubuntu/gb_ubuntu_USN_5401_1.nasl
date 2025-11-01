# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845354");
  script_cve_id("CVE-2021-3839", "CVE-2022-0669");
  script_tag(name:"creation_date", value:"2022-05-05 01:00:29 +0000 (Thu, 05 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5401-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5401-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5401-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dpdk' package(s) announced via the USN-5401-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wenxiang Qian discovered that DPDK incorrectly checked certain payloads. An
attacker could use this issue to cause DPDK to crash, resulting in a denial
of service, or possibly execute arbitrary code. (CVE-2021-3839)

It was discovered that DPDK incorrectly handled in type messages. An
attacker could possibly use this issue to cause DPDK to consume resources,
leading to a denial of service. (CVE-2022-0669)");

  script_tag(name:"affected", value:"'dpdk' package(s) on Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
