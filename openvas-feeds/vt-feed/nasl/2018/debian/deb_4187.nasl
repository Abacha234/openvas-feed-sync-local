# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704187");
  script_cve_id("CVE-2015-9016", "CVE-2017-0861", "CVE-2017-13166", "CVE-2017-13220", "CVE-2017-16526", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-18017", "CVE-2017-18203", "CVE-2017-18216", "CVE-2017-18232", "CVE-2017-18241", "CVE-2017-5715", "CVE-2017-5753", "CVE-2018-1000004", "CVE-2018-1000199", "CVE-2018-1066", "CVE-2018-1068", "CVE-2018-1092", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5750", "CVE-2018-5803", "CVE-2018-6927", "CVE-2018-7492", "CVE-2018-7566", "CVE-2018-7740", "CVE-2018-7757", "CVE-2018-7995", "CVE-2018-8781", "CVE-2018-8822");
  script_tag(name:"creation_date", value:"2018-04-30 22:00:00 +0000 (Mon, 30 Apr 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 20:40:00 +0000 (Fri, 22 Apr 2022)");

  script_name("Debian: Security Advisory (DSA-4187)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4187");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4187");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4187 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2015-9016

Ming Lei reported a race condition in the multiqueue block layer (blk-mq). On a system with a driver using blk-mq (mtip32xx, null_blk, or virtio_blk), a local user might be able to use this for denial of service or possibly for privilege escalation.

CVE-2017-0861

Robb Glasser reported a potential use-after-free in the ALSA (sound) PCM core. We believe this was not possible in practice.

CVE-2017-5715

Multiple researchers have discovered a vulnerability in various processors supporting speculative execution, enabling an attacker controlling an unprivileged process to read memory from arbitrary addresses, including from the kernel and all other processes running on the system.

This specific attack has been named Spectre variant 2 (branch target injection) and is mitigated for the x86 architecture (amd64 and i386) by using the retpoline compiler feature which allows indirect branches to be isolated from speculative execution.

CVE-2017-5753

Multiple researchers have discovered a vulnerability in various processors supporting speculative execution, enabling an attacker controlling an unprivileged process to read memory from arbitrary addresses, including from the kernel and all other processes running on the system.

This specific attack has been named Spectre variant 1 (bounds-check bypass) and is mitigated by identifying vulnerable code sections (array bounds checking followed by array access) and replacing the array access with the speculation-safe array_index_nospec() function.

More use sites will be added over time.

CVE-2017-13166

A bug in the 32-bit compatibility layer of the v4l2 ioctl handling code has been found. Memory protections ensuring user-provided buffers always point to userland memory were disabled, allowing destination addresses to be in kernel space. On a 64-bit kernel a local user with access to a suitable video device can exploit this to overwrite kernel memory, leading to privilege escalation.

CVE-2017-13220

Al Viro reported that the Bluetooth HIDP implementation could dereference a pointer before performing the necessary type check. A local user could use this to cause a denial of service.

CVE-2017-16526

Andrey Konovalov reported that the UWB subsystem may dereference an invalid pointer in an error case. A local user might be able to use this for denial of service.

CVE-2017-16911

Secunia Research reported that the USB/IP vhci_hcd driver exposed kernel heap addresses to local users. This information could aid the exploitation of other vulnerabilities.

CVE-2017-16912

Secunia Research reported that the USB/IP stub driver failed to perform a range check on a received packet header field, leading to an out-of-bounds read. A remote user able to connect to the USB/IP server could use ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);