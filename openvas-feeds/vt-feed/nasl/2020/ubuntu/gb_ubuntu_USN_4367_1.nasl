# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844438");
  script_cve_id("CVE-2019-19377", "CVE-2020-11565", "CVE-2020-12657", "CVE-2020-12826");
  script_tag(name:"creation_date", value:"2020-05-20 03:00:24 +0000 (Wed, 20 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-11 00:15:00 +0000 (Fri, 11 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4367-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4367-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4367-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gcp, linux-meta-kvm, linux-meta-oracle, linux-meta-riscv, linux-oracle, linux-riscv, linux-signed, linux-signed-gcp, linux-signed-oracle' package(s) announced via the USN-4367-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the btrfs implementation in the Linux kernel did not
properly detect that a block was marked dirty in some situations. An
attacker could use this to specially craft a file system image that, when
unmounted, could cause a denial of service (system crash). (CVE-2019-19377)

It was discovered that the linux kernel did not properly validate certain
mount options to the tmpfs virtual memory file system. A local attacker
with the ability to specify mount options could use this to cause a denial
of service (system crash). (CVE-2020-11565)

It was discovered that the block layer in the Linux kernel contained a race
condition leading to a use-after-free vulnerability. A local attacker could
possibly use this to cause a denial of service (system crash) or execute
arbitrary code. (CVE-2020-12657)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gcp, linux-meta-kvm, linux-meta-oracle, linux-meta-riscv, linux-oracle, linux-riscv, linux-signed, linux-signed-gcp, linux-signed-oracle' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
