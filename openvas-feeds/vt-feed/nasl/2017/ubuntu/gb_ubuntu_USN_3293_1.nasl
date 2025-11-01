# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843165");
  script_cve_id("CVE-2017-2596", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7477", "CVE-2017-7616");
  script_tag(name:"creation_date", value:"2017-05-17 04:52:48 +0000 (Wed, 17 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-12 01:29:00 +0000 (Thu, 12 Apr 2018)");

  script_name("Ubuntu: Security Advisory (USN-3293-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3293-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3293-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta, linux-meta-raspi2, linux-raspi2' package(s) announced via the USN-3293-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dmitry Vyukov discovered that KVM implementation in the Linux kernel
improperly emulated the VMXON instruction. A local attacker in a guest OS
could use this to cause a denial of service (memory consumption) in the
host OS. (CVE-2017-2596)

Dmitry Vyukov discovered that the generic SCSI (sg) subsystem in the Linux
kernel contained a stack-based buffer overflow. A local attacker with
access to an sg device could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2017-7187)

It was discovered that a NULL pointer dereference existed in the Direct
Rendering Manager (DRM) driver for VMWare devices in the Linux kernel. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2017-7261)

Li Qiang discovered that an integer overflow vulnerability existed in the
Direct Rendering Manager (DRM) driver for VMWare devices in the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2017-7294)

Jason Donenfeld discovered a heap overflow in the MACsec module in the
Linux kernel. An attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2017-7477)

It was discovered that an information leak existed in the set_mempolicy and
mbind compat syscalls in the Linux kernel. A local attacker could use this
to expose sensitive information (kernel memory). (CVE-2017-7616)");

  script_tag(name:"affected", value:"'linux, linux-meta, linux-meta-raspi2, linux-raspi2' package(s) on Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
