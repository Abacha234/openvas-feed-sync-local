# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845329");
  script_cve_id("CVE-2022-0494", "CVE-2022-0854", "CVE-2022-1011", "CVE-2022-1015", "CVE-2022-1016", "CVE-2022-1048", "CVE-2022-24958", "CVE-2022-26490", "CVE-2022-26966", "CVE-2022-27223", "CVE-2022-28356");
  script_tag(name:"creation_date", value:"2022-04-21 01:00:28 +0000 (Thu, 21 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-11 14:45:00 +0000 (Wed, 11 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5381-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5381-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5381-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta-oem-5.14, linux-oem-5.14, linux-signed-oem-5.14' package(s) announced via the USN-5381-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Bouman discovered that the netfilter subsystem in the Linux kernel
did not properly validate passed user register indices. A local attacker
could use this to cause a denial of service or possibly execute arbitrary
code. (CVE-2022-1015)

It was discovered that the block layer subsystem in the Linux kernel did
not properly initialize memory in some situations. A privileged local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2022-0494)

It was discovered that the DMA subsystem in the Linux kernel did not
properly ensure bounce buffers were completely overwritten by the DMA
device. A local attacker could use this to expose sensitive information
(kernel memory). (CVE-2022-0854)

Jann Horn discovered that the FUSE file system in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-1011)

David Bouman discovered that the netfilter subsystem in the Linux kernel
did not initialize memory in some situations. A local attacker could use
this to expose sensitive information (kernel memory). (CVE-2022-1016)

Hu Jiahui discovered that multiple race conditions existed in the Advanced
Linux Sound Architecture (ALSA) framework, leading to use-after-free
vulnerabilities. A local attacker could use these to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2022-1048)

It was discovered that the USB Gadget file system interface in the Linux
kernel contained a use-after-free vulnerability. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2022-24958)

It was discovered that the ST21NFCA NFC driver in the Linux kernel did not
properly validate the size of certain data in EVT_TRANSACTION events. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-26490)

It was discovered that the USB SR9700 ethernet device driver for the Linux
kernel did not properly validate the length of requests from the device. A
physically proximate attacker could possibly use this to expose sensitive
information (kernel memory). (CVE-2022-26966)

It was discovered that the Xilinx USB2 device gadget driver in the Linux
kernel did not properly validate endpoint indices from the host. A
physically proximate attacker could possibly use this to cause a denial of
service (system crash). (CVE-2022-27223)

Zhao Zi Xuan discovered that the 802.2 LLC type 2 driver in the Linux kernel did not
properly perform reference counting in some error conditions. A local
attacker could use this to cause a denial of service. (CVE-2022-28356)");

  script_tag(name:"affected", value:"'linux-meta-oem-5.14, linux-oem-5.14, linux-signed-oem-5.14' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
