# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843061");
  script_cve_id("CVE-2016-10088", "CVE-2016-9191", "CVE-2016-9588", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5549", "CVE-2017-6074");
  script_tag(name:"creation_date", value:"2017-02-22 14:14:45 +0000 (Wed, 22 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3208-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3208-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3208-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta, linux-meta-snapdragon, linux-snapdragon' package(s) announced via the USN-3208-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the generic SCSI block layer in the Linux kernel did
not properly restrict write operations in certain situations. A local
attacker could use this to cause a denial of service (system crash) or
possibly gain administrative privileges. (CVE-2016-10088)

CAI Qian discovered that the sysctl implementation in the Linux kernel did
not properly perform reference counting in some situations. An unprivileged
attacker could use this to cause a denial of service (system hang).
(CVE-2016-9191)

Jim Mattson discovered that the KVM implementation in the Linux kernel
mismanages the #BP and #OF exceptions. A local attacker in a guest virtual
machine could use this to cause a denial of service (guest OS crash).
(CVE-2016-9588)

Andy Lutomirski and Willy Tarreau discovered that the KVM implementation in
the Linux kernel did not properly emulate instructions on the SS segment
register. A local attacker in a guest virtual machine could use this to
cause a denial of service (guest OS crash) or possibly gain administrative
privileges in the guest OS. (CVE-2017-2583)

Dmitry Vyukov discovered that the KVM implementation in the Linux kernel
improperly emulated certain instructions. A local attacker could use this
to obtain sensitive information (kernel memory). (CVE-2017-2584)

It was discovered that the KLSI KL5KUSB105 serial-to-USB device driver in
the Linux kernel did not properly initialize memory related to logging. A
local attacker could use this to expose sensitive information (kernel
memory). (CVE-2017-5549)

Andrey Konovalov discovered a use-after-free vulnerability in the DCCP
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly gain administrative
privileges. (CVE-2017-6074)");

  script_tag(name:"affected", value:"'linux, linux-meta, linux-meta-snapdragon, linux-snapdragon' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
