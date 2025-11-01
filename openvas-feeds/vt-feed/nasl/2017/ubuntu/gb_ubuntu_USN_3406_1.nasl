# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843297");
  script_cve_id("CVE-2016-7914", "CVE-2017-7261", "CVE-2017-7273", "CVE-2017-7487", "CVE-2017-7495", "CVE-2017-7616");
  script_tag(name:"creation_date", value:"2017-08-29 06:05:48 +0000 (Tue, 29 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Ubuntu: Security Advisory (USN-3406-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3406-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3406-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta' package(s) announced via the USN-3406-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that an out of bounds read vulnerability existed in the
associative array implementation in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash) or expose
sensitive information. (CVE-2016-7914)

It was discovered that a NULL pointer dereference existed in the Direct
Rendering Manager (DRM) driver for VMWare devices in the Linux kernel. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2017-7261)

It was discovered that the USB Cypress HID drivers for the Linux kernel did
not properly validate reported information from the device. An attacker
with physical access could use this to expose sensitive information (kernel
memory). (CVE-2017-7273)

A reference count bug was discovered in the Linux kernel ipx protocol
stack. A local attacker could exploit this flaw to cause a denial of
service or possibly other unspecified problems. (CVE-2017-7487)

Huang Weller discovered that the ext4 filesystem implementation in the
Linux kernel mishandled a needs-flushing-before-commit list. A local
attacker could use this to expose sensitive information. (CVE-2017-7495)

It was discovered that an information leak existed in the set_mempolicy and
mbind compat syscalls in the Linux kernel. A local attacker could use this
to expose sensitive information (kernel memory). (CVE-2017-7616)");

  script_tag(name:"affected", value:"'linux, linux-meta' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
