# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817723");
  script_cve_id("CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2021-28688", "CVE-2021-28951", "CVE-2021-28952", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-28972", "CVE-2021-29264", "CVE-2021-29266", "CVE-2021-29646", "CVE-2021-29647", "CVE-2021-29649", "CVE-2021-29650", "CVE-2021-29657", "CVE-2021-31916", "CVE-2021-3483", "CVE-2021-3489", "CVE-2021-3490", "CVE-2021-3491");
  script_tag(name:"creation_date", value:"2021-05-12 03:00:32 +0000 (Wed, 12 May 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4948-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4948-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4948-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta-oem-5.10, linux-oem-5.10, linux-signed-oem-5.10' package(s) announced via the USN-4948-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ryota Shiga discovered that the eBPF implementation in the Linux kernel did
not properly verify that a BPF program only reserved as much memory for a
ring buffer as was allocated. A local attacker could use this to cause a
denial of service (system crash) or execute arbitrary code. (CVE-2021-3489)

Manfred Paul discovered that the eBPF implementation in the Linux kernel
did not properly track bounds on bitwise operations. A local attacker could
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2021-3490)

Billy Jheng Bing-Jhong discovered that the io_uring implementation of the
Linux kernel did not properly enforce the MAX_RW_COUNT limit in some
situations. A local attacker could use this to cause a denial of service
(system crash) or execute arbitrary code. (CVE-2021-3491)

Kiyin (Yin Liang ) discovered that the NFC LLCP protocol implementation in the
Linux kernel contained a reference counting error. A local attacker could
use this to cause a denial of service (system crash). (CVE-2020-25670)

Kiyin (Yin Liang ) discovered that the NFC LLCP protocol implementation in the
Linux kernel did not properly deallocate memory in certain error
situations. A local attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2020-25671, CVE-2020-25672)

It was discovered that the Xen paravirtualization backend in the Linux
kernel did not properly deallocate memory in some situations. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2021-28688)

It was discovered that the io_uring subsystem in the Linux kernel contained
a race condition leading to a deadlock condition. A local attacker could
use this to cause a denial of service. (CVE-2021-28951)

John Stultz discovered that the audio driver for Qualcomm SDM845 systems in
the Linux kernel did not properly validate port ID numbers. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-28952)

Zygo Blaxell discovered that the btrfs file system implementation in the
Linux kernel contained a race condition during certain cloning operations.
A local attacker could possibly use this to cause a denial of service
(system crash). (CVE-2021-28964)

Vince Weaver discovered that the perf subsystem in the Linux kernel did
not properly handle certain PEBS records properly for some Intel Haswell
processors. A local attacker could use this to cause a denial of service
(system crash). (CVE-2021-28971)

It was discovered that the RPA PCI Hotplug driver implementation in the
Linux kernel did not properly handle device name writes via sysfs, leading
to a buffer overflow. A privileged attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2021-28972)

It was discovered that the Freescale Gianfar Ethernet driver for the Linux
kernel did not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-meta-oem-5.10, linux-oem-5.10, linux-signed-oem-5.10' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
