# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892940");
  script_cve_id("CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-29264", "CVE-2021-33033", "CVE-2021-3640", "CVE-2021-3752", "CVE-2021-39685", "CVE-2021-39686", "CVE-2021-39698", "CVE-2021-39714", "CVE-2021-4002", "CVE-2021-4083", "CVE-2021-4155", "CVE-2021-4202", "CVE-2021-43976", "CVE-2021-45095", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0330", "CVE-2022-0435", "CVE-2022-0487", "CVE-2022-0492", "CVE-2022-0617", "CVE-2022-24448", "CVE-2022-25258", "CVE-2022-25375");
  script_tag(name:"creation_date", value:"2022-03-10 02:00:24 +0000 (Thu, 10 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:00 +0000 (Thu, 07 Apr 2022)");

  script_name("Debian: Security Advisory (DLA-2940)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2940");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2940");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-2940 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2021-3640

LinMa of BlockSec Team discovered a race condition in the Bluetooth SCO implementation that can lead to a use-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2021-3752

Likang Luo of NSFOCUS Security Team discovered a flaw in the Bluetooth L2CAP implementation that can lead to a user-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2021-4002

It was discovered that hugetlbfs, the virtual filesystem used by applications to allocate huge pages in RAM, did not flush the CPU's TLB in one case where it was necessary. In some circumstances a local user would be able to read and write huge pages after they are freed and reallocated to a different process. This could lead to privilege escalation, denial of service or information leaks.

CVE-2021-4083

Jann Horn reported a race condition in the local (Unix) sockets garbage collector, that can lead to use-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2021-4155

Kirill Tkhai discovered a data leak in the way the XFS_IOC_ALLOCSP IOCTL in the XFS filesystem allowed for a size increase of files with unaligned size. A local attacker can take advantage of this flaw to leak data on the XFS filesystem.

CVE-2021-4202

Lin Ma discovered a race condition in the NCI (NFC Controller Interface) driver, which could lead to a use-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

This protocol is not enabled in Debian's official kernel configurations.

CVE-2021-28711

, CVE-2021-28712, CVE-2021-28713 (XSA-391)

Juergen Gross reported that malicious PV backends can cause a denial of service to guests being serviced by those backends via high frequency events, even if those backends are running in a less privileged environment.

CVE-2021-28714

, CVE-2021-28715 (XSA-392)

Juergen Gross discovered that Xen guests can force the Linux netback driver to hog large amounts of kernel memory, resulting in denial of service.

CVE-2021-29264

It was discovered that the gianfar Ethernet driver used with some Freescale SoCs did not correctly handle a Rx queue overrun when jumbo packets were enabled. On systems using this driver and jumbo packets, an attacker on the network could exploit this to cause a denial of service (crash).

This driver is not enabled in Debian's official kernel configurations.

CVE-2021-33033

The syzbot tool found a reference counting bug in the CIPSO implementation that can lead to a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);