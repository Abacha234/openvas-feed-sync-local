# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840677");
  script_cve_id("CVE-2011-1750", "CVE-2011-1751");
  script_tag(name:"creation_date", value:"2011-06-20 06:37:08 +0000 (Mon, 20 Jun 2011)");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1145-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1145-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1145-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the USN-1145-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that QEMU did not properly perform validation of I/O
operations from the guest which could lead to heap corruption. An attacker
could exploit this to cause a denial of service of the guest or possibly
execute code with the privileges of the user invoking the program.
(CVE-2011-1750)

Nelson Elhage discovered that QEMU did not properly handle memory when
removing ISA devices. An attacker could exploit this to cause a denial of
service of the guest or possibly execute code with the privileges of the
user invoking the program. (CVE-2011-1751)

When using QEMU with libvirt or virtualization management software based on
libvirt such as Eucalyptus and OpenStack, QEMU guests are individually isolated
by an AppArmor profile by default in Ubuntu.");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
