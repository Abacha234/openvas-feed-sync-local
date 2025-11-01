# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844121");
  script_cve_id("CVE-2019-11487", "CVE-2019-11599", "CVE-2019-11833", "CVE-2019-11884");
  script_tag(name:"creation_date", value:"2019-08-02 02:00:28 +0000 (Fri, 02 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4069-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4069-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4069-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-hwe, linux-meta-hwe, linux-signed-hwe' package(s) announced via the USN-4069-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4069-1 fixed vulnerabilities in the Linux kernel for Ubuntu 19.04.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 19.04 for Ubuntu 18.04 LTS.

It was discovered that an integer overflow existed in the Linux kernel when
reference counting pages, leading to potential use-after-free issues. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2019-11487)

Jann Horn discovered that a race condition existed in the Linux kernel when
performing core dumps. A local attacker could use this to cause a denial of
service (system crash) or expose sensitive information. (CVE-2019-11599)

It was discovered that the ext4 file system implementation in the Linux
kernel did not properly zero out memory in some situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2019-11833)

It was discovered that the Bluetooth Human Interface Device Protocol (HIDP)
implementation in the Linux kernel did not properly verify strings were
NULL terminated in certain situations. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2019-11884)");

  script_tag(name:"affected", value:"'linux-hwe, linux-meta-hwe, linux-signed-hwe' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
