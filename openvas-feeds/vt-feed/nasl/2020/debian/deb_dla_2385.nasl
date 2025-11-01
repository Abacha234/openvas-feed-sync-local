# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892385");
  script_cve_id("CVE-2019-19448", "CVE-2019-19813", "CVE-2019-19816", "CVE-2019-3874", "CVE-2020-10781", "CVE-2020-12888", "CVE-2020-14314", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-14385", "CVE-2020-14386", "CVE-2020-14390", "CVE-2020-16166", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-25285", "CVE-2020-25641", "CVE-2020-26088");
  script_tag(name:"creation_date", value:"2020-09-29 03:00:40 +0000 (Tue, 29 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-15 22:27:00 +0000 (Mon, 15 Mar 2021)");

  script_name("Debian: Security Advisory (DLA-2385)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2385");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2385");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux-4.19");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.19' package(s) announced via the DLA-2385 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service, or information leak.

CVE-2019-3874

Kernel buffers allocated by the SCTP network protocol were not limited by the memory cgroup controller. A local user could potentially use this to evade container memory limits and to cause a denial of service (excessive memory use).

CVE-2019-19448, CVE-2019-19813, CVE-2019-19816 Team bobfuzzer reported bugs in Btrfs that could lead to a use-after-free or heap buffer overflow, and could be triggered by crafted filesystem images. A user permitted to mount and access arbitrary filesystems could use these to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-10781

Luca Bruno of Red Hat discovered that the zram control file /sys/class/zram-control/hot_add was readable by all users. On a system with zram enabled, a local user could use this to cause a denial of service (memory exhaustion).

CVE-2020-12888

It was discovered that the PCIe Virtual Function I/O (vfio-pci) driver allowed users to disable a device's memory space while it was still mapped into a process. On some hardware platforms, local users or guest virtual machines permitted to access PCIe Virtual Functions could use this to cause a denial of service (hardware error and crash).

CVE-2020-14314

A bug was discovered in the ext4 filesystem that could lead to an out-of-bound read. A local user permitted to mount and access arbitrary filesystem images could use this to cause a denial of service (crash).

CVE-2020-14331

A bug was discovered in the VGA console driver's soft-scrollback feature that could lead to a heap buffer overflow. On a system with a custom kernel that has CONFIG_VGACON_SOFT_SCROLLBACK enabled, a local user with access to a console could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-14356

A bug was discovered in the cgroup subsystem's handling of socket references to cgroups. In some cgroup configurations, this could lead to a use-after-free. A local user might be able to use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-14385

A bug was discovered in XFS, which could lead to an extended attribute (xattr) wrongly being detected as invalid. A local user with access to an XFS filesystem could use this to cause a denial of service (filesystem shutdown).

CVE-2020-14386

Or Cohen discovered a bug in the packet socket (AF_PACKET) implementation which could lead to a heap buffer overflow. A local user with the CAP_NET_RAW capability (in any user namespace) could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-14390

Minh Yuan discovered a bug in the framebuffer console driver's scrollback ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-4.19' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);