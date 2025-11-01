# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845056");
  script_cve_id("CVE-2021-34693", "CVE-2021-3612", "CVE-2021-3653", "CVE-2021-3656", "CVE-2021-38160");
  script_tag(name:"creation_date", value:"2021-09-11 01:00:32 +0000 (Sat, 11 Sep 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 18:55:00 +0000 (Thu, 10 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5073-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5073-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5073-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-kvm, linux-meta-oracle, linux-meta-snapdragon, linux-oracle, linux-signed, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-5073-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Maxim Levitsky and Paolo Bonzini discovered that the KVM hypervisor
implementation for AMD processors in the Linux kernel allowed a guest VM to
disable restrictions on VMLOAD/VMSAVE in a nested guest. An attacker in a
guest VM could use this to read or write portions of the host's physical
memory. (CVE-2021-3656)

Maxim Levitsky discovered that the KVM hypervisor implementation for AMD
processors in the Linux kernel did not properly prevent a guest VM from
enabling AVIC in nested guest VMs. An attacker in a guest VM could use this
to write to portions of the host's physical memory. (CVE-2021-3653)

Norbert Slusarek discovered that the CAN broadcast manager (bcm) protocol
implementation in the Linux kernel did not properly initialize memory in
some situations. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2021-34693)

Murray McAllister discovered that the joystick device interface in the
Linux kernel did not properly validate data passed via an ioctl(). A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code on systems with a joystick device
registered. (CVE-2021-3612)

It was discovered that the Virtio console implementation in the Linux
kernel did not properly validate input lengths in some situations. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2021-38160)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-kvm, linux-meta-oracle, linux-meta-snapdragon, linux-oracle, linux-signed, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
