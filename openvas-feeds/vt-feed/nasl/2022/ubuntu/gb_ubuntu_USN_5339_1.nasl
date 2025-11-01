# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845287");
  script_cve_id("CVE-2021-3506", "CVE-2021-43976", "CVE-2021-44733", "CVE-2021-45095", "CVE-2022-0435", "CVE-2022-0492");
  script_tag(name:"creation_date", value:"2022-03-23 02:00:34 +0000 (Wed, 23 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:00 +0000 (Thu, 07 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5339-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5339-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-aws, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-5339-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yiqi Sun and Kevin Wang discovered that the cgroups implementation in the
Linux kernel did not properly restrict access to the cgroups v1
release_agent feature. A local attacker could use this to gain
administrative privileges. (CVE-2022-0492)

It was discovered that an out-of-bounds (OOB) memory access flaw existed in
the f2fs module of the Linux kernel. A local attacker could use this issue
to cause a denial of service (system crash). (CVE-2021-3506)

Brendan Dolan-Gavitt discovered that the Marvell WiFi-Ex USB device driver
in the Linux kernel did not properly handle some error conditions. A
physically proximate attacker could use this to cause a denial of service
(system crash). (CVE-2021-43976)

It was discovered that the ARM Trusted Execution Environment (TEE)
subsystem in the Linux kernel contained a race condition leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service or possibly execute arbitrary code. (CVE-2021-44733)

It was discovered that the Phone Network protocol (PhoNet) implementation
in the Linux kernel did not properly perform reference counting in some
error conditions. A local attacker could possibly use this to cause a
denial of service (memory exhaustion). (CVE-2021-45095)

Samuel Page discovered that the Transparent Inter-Process Communication
(TIPC) protocol implementation in the Linux kernel contained a stack-based
buffer overflow. A remote attacker could use this to cause a denial of
service (system crash) for systems that have a TIPC bearer configured.
(CVE-2022-0435)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-aws, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
