# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845107");
  script_cve_id("CVE-2020-3702", "CVE-2021-3732", "CVE-2021-38198", "CVE-2021-38205", "CVE-2021-40490", "CVE-2021-42008");
  script_tag(name:"creation_date", value:"2021-10-21 01:01:30 +0000 (Thu, 21 Oct 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 18:36:00 +0000 (Tue, 12 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5116-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5116-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5116-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-bluefield, linux-gcp-5.4, linux-hwe-5.4, linux-kvm, linux-meta, linux-meta-bluefield, linux-meta-gcp-5.4, linux-meta-hwe-5.4, linux-meta-kvm, linux-signed, linux-signed-bluefield, linux-signed-gcp-5.4, linux-signed-hwe-5.4, linux-signed-kvm' package(s) announced via the USN-5116-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the Atheros Ath9k WiFi
driver in the Linux kernel. An attacker could possibly use this to expose
sensitive information (WiFi network traffic). (CVE-2020-3702)

Alois Wohlschlager discovered that the overlay file system in the Linux
kernel did not restrict private clones in some situations. An attacker
could use this to expose sensitive information. (CVE-2021-3732)

It was discovered that the KVM hypervisor implementation in the Linux
kernel did not properly compute the access permissions for shadow pages in
some situations. A local attacker could use this to cause a denial of
service. (CVE-2021-38198)

It was discovered that the Xilinx 10/100 Ethernet Lite device driver in the
Linux kernel could report pointer addresses in some situations. An attacker
could use this information to ease the exploitation of another
vulnerability. (CVE-2021-38205)

It was discovered that the ext4 file system in the Linux kernel contained a
race condition when writing xattrs to an inode. A local attacker could use
this to cause a denial of service or possibly gain administrative
privileges. (CVE-2021-40490)

It was discovered that the 6pack network protocol driver in the Linux
kernel did not properly perform validation checks. A privileged attacker
could use this to cause a denial of service (system crash) or execute
arbitrary code. (CVE-2021-42008)");

  script_tag(name:"affected", value:"'linux, linux-bluefield, linux-gcp-5.4, linux-hwe-5.4, linux-kvm, linux-meta, linux-meta-bluefield, linux-meta-gcp-5.4, linux-meta-hwe-5.4, linux-meta-kvm, linux-signed, linux-signed-bluefield, linux-signed-gcp-5.4, linux-signed-hwe-5.4, linux-signed-kvm' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
