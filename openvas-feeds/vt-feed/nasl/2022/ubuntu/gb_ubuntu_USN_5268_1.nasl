# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845232");
  script_cve_id("CVE-2021-20322", "CVE-2021-3640", "CVE-2021-3752", "CVE-2021-42739");
  script_tag(name:"creation_date", value:"2022-02-03 10:10:20 +0000 (Thu, 03 Feb 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-01 19:33:00 +0000 (Tue, 01 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5268-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5268-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5268-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-dell300x, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-5268-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Keyu Man discovered that the ICMP implementation in the Linux kernel did
not properly handle received ICMP error packets. A remote attacker could
use this to facilitate attacks on UDP based services that depend on source
port randomization. (CVE-2021-20322)

It was discovered that the Bluetooth subsystem in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2021-3640)

Likang Luo discovered that a race condition existed in the Bluetooth
subsystem of the Linux kernel, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2021-3752)

Luo Likang discovered that the FireDTV Firewire driver in the Linux kernel
did not properly perform bounds checking in some situations. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-42739)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-dell300x, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
