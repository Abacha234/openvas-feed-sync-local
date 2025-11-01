# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845327");
  script_cve_id("CVE-2021-43976", "CVE-2021-44879", "CVE-2022-0617", "CVE-2022-1015", "CVE-2022-1016", "CVE-2022-24448", "CVE-2022-24959", "CVE-2022-26878");
  script_tag(name:"creation_date", value:"2022-04-21 01:00:22 +0000 (Thu, 21 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-11 14:42:00 +0000 (Wed, 11 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5383-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5383-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5383-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.13, linux-azure, linux-azure-5.13, linux-gcp, linux-gcp-5.13, linux-hwe-5.13, linux-intel-5.13, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.13, linux-meta-azure, linux-meta-azure-5.13, linux-meta-gcp, linux-meta-gcp-5.13, linux-meta-hwe-5.13, linux-meta-intel-5.13, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.13, linux-meta-raspi, linux-oracle, linux-oracle-5.13, linux-raspi, linux-signed, linux-signed-aws, linux-signed-aws-5.13, linux-signed-azure, linux-signed-azure-5.13, linux-signed-gcp, linux-signed-gcp-5.13, linux-signed-hwe-5.13, linux-signed-intel-5.13, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.13' package(s) announced via the USN-5383-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Bouman discovered that the netfilter subsystem in the Linux kernel
did not properly validate passed user register indices. A local attacker
could use this to cause a denial of service or possibly execute arbitrary
code. (CVE-2022-1015)

Brendan Dolan-Gavitt discovered that the Marvell WiFi-Ex USB device driver
in the Linux kernel did not properly handle some error conditions. A
physically proximate attacker could use this to cause a denial of service
(system crash). (CVE-2021-43976)

Wenqing Liu discovered that the f2fs file system implementation in the
Linux kernel did not properly validate inode types while performing garbage
collection. An attacker could use this to construct a malicious f2fs image
that, when mounted and operated on, could cause a denial of service (system
crash). (CVE-2021-44879)

It was discovered that the UDF file system implementation in the Linux
kernel could attempt to dereference a null pointer in some situations. An
attacker could use this to construct a malicious UDF image that, when
mounted and operated on, could cause a denial of service (system crash).
(CVE-2022-0617)

David Bouman discovered that the netfilter subsystem in the Linux kernel
did not initialize memory in some situations. A local attacker could use
this to expose sensitive information (kernel memory). (CVE-2022-1016)

Lyu Tao discovered that the NFS implementation in the Linux kernel did not
properly handle requests to open a directory on a regular file. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2022-24448)

It was discovered that the VirtIO Bluetooth driver in the Linux kernel did
not properly deallocate memory in some error conditions. A local attacker
could possibly use this to cause a denial of service (memory exhaustion).
(CVE-2022-26878)

It was discovered that the YAM AX.25 device driver in the Linux kernel did
not properly deallocate memory in some error conditions. A local privileged
attacker could use this to cause a denial of service (kernel memory
exhaustion). (CVE-2022-24959)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.13, linux-azure, linux-azure-5.13, linux-gcp, linux-gcp-5.13, linux-hwe-5.13, linux-intel-5.13, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.13, linux-meta-azure, linux-meta-azure-5.13, linux-meta-gcp, linux-meta-gcp-5.13, linux-meta-hwe-5.13, linux-meta-intel-5.13, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.13, linux-meta-raspi, linux-oracle, linux-oracle-5.13, linux-raspi, linux-signed, linux-signed-aws, linux-signed-aws-5.13, linux-signed-azure, linux-signed-azure-5.13, linux-signed-gcp, linux-signed-gcp-5.13, linux-signed-hwe-5.13, linux-signed-intel-5.13, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.13' package(s) on Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
