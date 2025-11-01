# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892420");
  script_cve_id("CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19448", "CVE-2019-9445", "CVE-2020-12351", "CVE-2020-12352", "CVE-2020-12655", "CVE-2020-12771", "CVE-2020-12888", "CVE-2020-14305", "CVE-2020-14314", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-14386", "CVE-2020-14390", "CVE-2020-15393", "CVE-2020-16166", "CVE-2020-24490", "CVE-2020-25211", "CVE-2020-25212", "CVE-2020-25220", "CVE-2020-25284", "CVE-2020-25285", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-26088");
  script_tag(name:"creation_date", value:"2020-10-31 04:00:34 +0000 (Sat, 31 Oct 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-08 16:15:00 +0000 (Thu, 08 Apr 2021)");

  script_name("Debian: Security Advisory (DLA-2420)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2420");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2420-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-2420 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update corrects a regression in some Xen virtual machine environments. For reference the original advisory text follows.

Several vulnerabilities have been discovered in the Linux kernel that may lead to the execution of arbitrary code, privilege escalation, denial of service or information leaks.

CVE-2019-9445

A potential out-of-bounds read was discovered in the F2FS implementation. A user permitted to mount and access arbitrary filesystems could potentially use this to cause a denial of service (crash) or to read sensitive information.

CVE-2019-19073, CVE-2019-19074 Navid Emamdoost discovered potential memory leaks in the ath9k and ath9k_htc drivers. The security impact of these is unclear.

CVE-2019-19448

Team bobfuzzer reported a bug in Btrfs that could lead to a use-after-free, and could be triggered by crafted filesystem images. A user permitted to mount and access arbitrary filesystems could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-12351

Andy Nguyen discovered a flaw in the Bluetooth implementation in the way L2CAP packets with A2MP CID are handled. A remote attacker within a short distance, knowing the victim's Bluetooth device address, can send a malicious l2cap packet and cause a denial of service or possibly arbitrary code execution with kernel privileges.

CVE-2020-12352

Andy Nguyen discovered a flaw in the Bluetooth implementation. Stack memory is not properly initialised when handling certain AMP packets. A remote attacker within a short distance, knowing the victim's Bluetooth device address address, can retrieve kernel stack information.

CVE-2020-12655

Zheng Bin reported that crafted XFS volumes could trigger a system hang. An attacker able to mount such a volume could use this to cause a denial of service.

CVE-2020-12771

Zhiqiang Liu reported a bug in the bcache block driver that could lead to a system hang. The security impact of this is unclear.

CVE-2020-12888

It was discovered that the PCIe Virtual Function I/O (vfio-pci) driver allowed users to disable a device's memory space while it was still mapped into a process. On some hardware platforms, local users or guest virtual machines permitted to access PCIe Virtual Functions could use this to cause a denial of service (hardware error and crash).

CVE-2020-14305

Vasily Averin of Virtuozzo discovered a potential heap buffer overflow in the netfilter nf_contrack_h323 module. When this module is used to perform connection tracking for TCP/IPv6, a remote attacker could use this to cause a denial of service (crash or memory corruption) or possibly for remote code execution with kernel privilege.

CVE-2020-14314

A bug was discovered in the ext4 filesystem that could lead to an out-of-bound read. A local user permitted to mount and access arbitrary filesystem images could use this to cause a denial of service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);