# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893065");
  script_cve_id("CVE-2018-1108", "CVE-2021-39713", "CVE-2021-4149", "CVE-2022-0494", "CVE-2022-0812", "CVE-2022-0854", "CVE-2022-1011", "CVE-2022-1012", "CVE-2022-1016", "CVE-2022-1198", "CVE-2022-1199", "CVE-2022-1353", "CVE-2022-1516", "CVE-2022-1729", "CVE-2022-1734", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166", "CVE-2022-2153", "CVE-2022-23036", "CVE-2022-23037", "CVE-2022-23038", "CVE-2022-23039", "CVE-2022-23040", "CVE-2022-23041", "CVE-2022-23042", "CVE-2022-23960", "CVE-2022-24958", "CVE-2022-26490", "CVE-2022-26966", "CVE-2022-27223", "CVE-2022-28356", "CVE-2022-28390", "CVE-2022-30594", "CVE-2022-32250", "CVE-2022-32296", "CVE-2022-33981");
  script_tag(name:"creation_date", value:"2022-07-02 01:00:37 +0000 (Sat, 02 Jul 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-12 02:27:00 +0000 (Sun, 12 Jun 2022)");

  script_name("Debian: Security Advisory (DLA-3065)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3065");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3065");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-3065 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

This update is unfortunately not available for the armel architecture.

CVE-2018-1108

It was discovered that the random driver could generate random bytes through /dev/random and the getrandom() system call before gathering enough entropy that these would be unpredictable. This could compromise the confidentiality and integrity of encrypted communications.

The original fix for this issue had to be reverted because it caused the boot process to hang on many systems. In this version, the random driver has been updated, making it more effective in gathering entropy without needing a hardware RNG.

CVE-2021-4149

Hao Sun reported a flaw in the Btrfs fileysstem driver. There is a potential lock imbalance in an error path. A local user might be able to exploit this for denial of service.

CVE-2021-39713

The syzbot tool found a race condition in the network scheduling subsystem which could lead to a use-after-free. A local user could exploit this for denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2022-0494

The scsi_ioctl() was susceptible to an information leak only exploitable by users with CAP_SYS_ADMIN or CAP_SYS_RAWIO capabilities.

CVE-2022-0812

It was discovered that the RDMA transport for NFS (xprtrdma) miscalculated the size of message headers, which could lead to a leak of sensitive information between NFS servers and clients.

CVE-2022-0854

Ali Haider discovered a potential information leak in the DMA subsystem. On systems where the swiotlb feature is needed, this might allow a local user to read sensitive information.

CVE-2022-1011

Jann Horn discovered a flaw in the FUSE (Filesystem in User-Space) implementation. A local user permitted to mount FUSE filesystems could exploit this to cause a use-after-free and read sensitive information.

CVE-2022-1012

, CVE-2022-32296

Moshe Kol, Amit Klein, and Yossi Gilad discovered a weakness in randomisation of TCP source port selection.

CVE-2022-1016

David Bouman discovered a flaw in the netfilter subsystem where the nft_do_chain function did not initialize register data that nf_tables expressions can read from and write to. A local attacker can take advantage of this to read sensitive information.

CVE-2022-1198

Duoming Zhou discovered a race condition in the 6pack hamradio driver, which could lead to a use-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2022-1199

Duoming Zhou discovered race conditions in the AX.25 hamradio protocol, which could lead to a use-after-free or null pointer dereference. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);