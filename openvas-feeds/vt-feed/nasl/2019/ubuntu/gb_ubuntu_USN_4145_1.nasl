# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844192");
  script_cve_id("CVE-2016-10905", "CVE-2017-18509", "CVE-2018-20961", "CVE-2018-20976", "CVE-2019-0136", "CVE-2019-10207", "CVE-2019-11487", "CVE-2019-13631", "CVE-2019-15211", "CVE-2019-15215", "CVE-2019-15926");
  script_tag(name:"creation_date", value:"2019-10-02 02:00:41 +0000 (Wed, 02 Oct 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-27 09:15:00 +0000 (Tue, 27 Aug 2019)");

  script_name("Ubuntu: Security Advisory (USN-4145-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4145-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4145-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) announced via the USN-4145-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the GFS2 file system in
the Linux kernel. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2016-10905)

It was discovered that the IPv6 implementation in the Linux kernel did not
properly validate socket options in some situations. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-18509)

It was discovered that the USB gadget Midi driver in the Linux kernel
contained a double-free vulnerability when handling certain error
conditions. A local attacker could use this to cause a denial of service
(system crash). (CVE-2018-20961)

It was discovered that the XFS file system in the Linux kernel did not
properly handle mount failures in some situations. A local attacker could
possibly use this to cause a denial of service (system crash) or execute
arbitrary code. (CVE-2018-20976)

It was discovered that the Intel Wi-Fi device driver in the Linux kernel
did not properly validate certain Tunneled Direct Link Setup (TDLS). A
physically proximate attacker could use this to cause a denial of service
(Wi-Fi disconnect). (CVE-2019-0136)

It was discovered that the Bluetooth UART implementation in the Linux
kernel did not properly check for missing tty operations. A local attacker
could use this to cause a denial of service. (CVE-2019-10207)

It was discovered that an integer overflow existed in the Linux kernel when
reference counting pages, leading to potential use-after-free issues. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2019-11487)

It was discovered that the GTCO tablet input driver in the Linux kernel did
not properly bounds check the initial HID report sent by the device. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-13631)

It was discovered that the Raremono AM/FM/SW radio device driver in the
Linux kernel did not properly allocate memory, leading to a use-after-free.
A physically proximate attacker could use this to cause a denial of service
or possibly execute arbitrary code. (CVE-2019-15211)

It was discovered that a race condition existed in the CPiA2 video4linux
device driver for the Linux kernel, leading to a use-after-free. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-15215)

It was discovered that the Atheros mobile chipset driver in the Linux
kernel did not properly validate data in some situations. An attacker could
use this to cause a denial of service (system crash). (CVE-2019-15926)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
