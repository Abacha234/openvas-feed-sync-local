# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845461");
  script_cve_id("CVE-2022-1652", "CVE-2022-1679", "CVE-2022-28893", "CVE-2022-34918");
  script_tag(name:"creation_date", value:"2022-08-03 01:00:42 +0000 (Wed, 03 Aug 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 14:00:00 +0000 (Wed, 13 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-5544-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5544-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5544-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-hwe-5.15, linux-lowlatency, linux-lowlatency-hwe-5.15, linux-meta, linux-meta-hwe-5.15, linux-meta-lowlatency, linux-meta-lowlatency-hwe-5.15, linux-signed, linux-signed-hwe-5.15, linux-signed-lowlatency, linux-signed-lowlatency-hwe-5.15' package(s) announced via the USN-5544-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Atheros ath9k wireless device driver in the
Linux kernel did not properly handle some error conditions, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-1679)

Felix Fu discovered that the Sun RPC implementation in the Linux kernel did
not properly handle socket states, leading to a use-after-free
vulnerability. A remote attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2022-28893)

Arthur Mongodin discovered that the netfilter subsystem in the Linux kernel
did not properly perform data validation. A local attacker could use this
to escalate privileges in certain situations. (CVE-2022-34918)

Minh Yuan discovered that the floppy disk driver in the Linux kernel
contained a race condition, leading to a use-after-free vulnerability. A
local attacker could possibly use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2022-1652)");

  script_tag(name:"affected", value:"'linux, linux-hwe-5.15, linux-lowlatency, linux-lowlatency-hwe-5.15, linux-meta, linux-meta-hwe-5.15, linux-meta-lowlatency, linux-meta-lowlatency-hwe-5.15, linux-signed, linux-signed-hwe-5.15, linux-signed-lowlatency, linux-signed-lowlatency-hwe-5.15' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
