# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891919");
  script_cve_id("CVE-2019-0136", "CVE-2019-11487", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15292", "CVE-2019-15538", "CVE-2019-15666", "CVE-2019-15807", "CVE-2019-15924", "CVE-2019-15926", "CVE-2019-9506");
  script_tag(name:"creation_date", value:"2019-09-14 02:00:24 +0000 (Sat, 14 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 16:14:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-1919)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1919");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1919-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.9' package(s) announced via the DLA-1919 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

This updated advisory text mentions the additional non-security changes and notes the need to install new binary packages.

CVE-2019-0136

It was discovered that the wifi soft-MAC implementation (mac80211) did not properly authenticate Tunneled Direct Link Setup (TDLS) messages. A nearby attacker could use this for denial of service (loss of wifi connectivity).

CVE-2019-9506

Daniele Antonioli, Nils Ole Tippenhauer, and Kasper Rasmussen discovered a weakness in the Bluetooth pairing protocols, dubbed the KNOB attack. An attacker that is nearby during pairing could use this to weaken the encryption used between the paired devices, and then to eavesdrop on and/or spoof communication between them.

This update mitigates the attack by requiring a minimum encryption key length of 56 bits.

CVE-2019-11487

Jann Horn discovered that the FUSE (Filesystem-in-Userspace) facility could be used to cause integer overflow in page reference counts, leading to a use-after-free. On a system with sufficient physical memory, a local user permitted to create arbitrary FUSE mounts could use this for privilege escalation.

By default, unprivileged users can only mount FUSE filesystems through fusermount, which limits the number of mounts created and should completely mitigate the issue.

CVE-2019-15211

The syzkaller tool found a bug in the radio-raremono driver that could lead to a use-after-free. An attacker able to add and remove USB devices could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2019-15212

The syzkaller tool found that the rio500 driver does not work correctly if more than one device is bound to it. An attacker able to add USB devices could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2019-15215

The syzkaller tool found a bug in the cpia2_usb driver that leads to a use-after-free. An attacker able to add and remove USB devices could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2019-15216

The syzkaller tool found a bug in the yurex driver that leads to a use-after-free. An attacker able to add and remove USB devices could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2019-15218

The syzkaller tool found that the smsusb driver did not validate that USB devices have the expected endpoints, potentially leading to a null pointer dereference. An attacker able to add USB devices could use this to cause a denial of service (BUG/oops).

CVE-2019-15219

The syzkaller tool found that a device initialisation error in the sisusbvga driver could lead to a null pointer dereference. An ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-4.9' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);