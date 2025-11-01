# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891930");
  script_cve_id("CVE-2016-10905", "CVE-2018-20976", "CVE-2018-21008", "CVE-2019-0136", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15215", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15292", "CVE-2019-15807", "CVE-2019-15917", "CVE-2019-15926", "CVE-2019-9506");
  script_tag(name:"creation_date", value:"2019-09-26 02:00:36 +0000 (Thu, 26 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 16:14:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-1930)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1930");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1930");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-1930 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2016-10905

A race condition was discovered in the GFS2 file-system implementation, which could lead to a use-after-free. On a system using GFS2, a local attacker could use this for denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2018-20976

It was discovered that the XFS file-system implementation did not correctly handle some mount failure conditions, which could lead to a use-after-free. The security impact of this is unclear.

CVE-2018-21008

It was discovered that the rsi wifi driver did not correctly handle some failure conditions, which could lead to a use-after-free. The security impact of this is unclear.

CVE-2019-0136

It was discovered that the wifi soft-MAC implementation (mac80211) did not properly authenticate Tunneled Direct Link Setup (TDLS) messages. A nearby attacker could use this for denial of service (loss of wifi connectivity).

CVE-2019-9506

Daniele Antonioli, Nils Ole Tippenhauer, and Kasper Rasmussen discovered a weakness in the Bluetooth pairing protocols, dubbed the KNOB attack. An attacker that is nearby during pairing could use this to weaken the encryption used between the paired devices, and then to eavesdrop on and/or spoof communication between them.

This update mitigates the attack by requiring a minimum encryption key length of 56 bits.

CVE-2019-14814, CVE-2019-14815, CVE-2019-14816 Multiple bugs were discovered in the mwifiex wifi driver, which could lead to heap buffer overflows. A local user permitted to configure a device handled by this driver could probably use this for privilege escalation.

CVE-2019-14821

Matt Delco reported a race condition in KVM's coalesced MMIO facility, which could lead to out-of-bounds access in the kernel. A local attacker permitted to access /dev/kvm could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2019-14835

Peter Pi of Tencent Blade Team discovered a missing bounds check in vhost_net, the network back-end driver for KVM hosts, leading to a buffer overflow when the host begins live migration of a VM. An attacker in control of a VM could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation on the host.

CVE-2019-15117

Hui Peng and Mathias Payer reported a missing bounds check in the usb-audio driver's descriptor parsing code, leading to a buffer over-read. An attacker able to add USB devices could possibly use this to cause a denial of service (crash).

CVE-2019-15118

Hui Peng and Mathias Payer reported unbounded recursion in the usb-audio driver's descriptor parsing code, leading to a stack overflow. An attacker able to add USB devices could use this to cause a denial of service (memory ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);