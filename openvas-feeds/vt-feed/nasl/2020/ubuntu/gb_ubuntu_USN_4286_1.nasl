# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844342");
  script_cve_id("CVE-2019-14615", "CVE-2019-15217", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-17351", "CVE-2019-19051", "CVE-2019-19056", "CVE-2019-19066", "CVE-2019-19068", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-5108");
  script_tag(name:"creation_date", value:"2020-02-19 04:00:45 +0000 (Wed, 19 Feb 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4286-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4286-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4286-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) announced via the USN-4286-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not properly clear data
structures on context switches for certain Intel graphics processors. A
local attacker could use this to expose sensitive information.
(CVE-2019-14615)

It was discovered that a race condition existed in the Softmac USB Prism54
device driver in the Linux kernel. A physically proximate attacker could
use this to cause a denial of service (system crash). (CVE-2019-15220)

Julien Grall discovered that the Xen balloon memory driver in the Linux
kernel did not properly restrict the amount of memory set aside for page
mappings in some situations. An attacker could use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-17351)

It was discovered that the Intel WiMAX 2400 driver in the Linux kernel did
not properly deallocate memory in certain situations. A local attacker
could use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19051)

It was discovered that the Marvell Wi-Fi device driver in the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to possibly cause a denial of service (kernel
memory exhaustion). (CVE-2019-19056)

It was discovered that the Brocade BFA Fibre Channel device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-19066)

It was discovered that the Realtek RTL8xxx USB Wi-Fi device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-19068)

Gao Chuan discovered that the SAS Class driver in the Linux kernel
contained a race condition that could lead to a NULL pointer dereference. A
local attacker could possibly use this to cause a denial of service (system
crash). (CVE-2019-19965)

It was discovered that the Datagram Congestion Control Protocol (DCCP)
implementation in the Linux kernel did not properly deallocate memory in
certain error conditions. An attacker could possibly use this to cause a
denial of service (kernel memory exhaustion). (CVE-2019-20096)

Mitchell Frank discovered that the Wi-Fi implementation in the Linux kernel
when used as an access point would send IAPP location updates for stations
before client authentication had completed. A physically proximate attacker
could use this to cause a denial of service. (CVE-2019-5108)

It was discovered that ZR364XX Camera USB device driver for the Linux
kernel did not properly initialize memory. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2019-15217)

It was discovered that the Line 6 POD USB device driver in the Linux kernel
did not properly validate data size information from the device. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
