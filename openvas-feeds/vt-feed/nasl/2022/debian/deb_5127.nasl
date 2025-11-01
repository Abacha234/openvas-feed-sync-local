# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705127");
  script_cve_id("CVE-2021-4197", "CVE-2022-0168", "CVE-2022-1016", "CVE-2022-1048", "CVE-2022-1158", "CVE-2022-1195", "CVE-2022-1198", "CVE-2022-1199", "CVE-2022-1204", "CVE-2022-1205", "CVE-2022-1353", "CVE-2022-1516", "CVE-2022-26490", "CVE-2022-27666", "CVE-2022-28356", "CVE-2022-28388", "CVE-2022-28389", "CVE-2022-28390", "CVE-2022-29582");
  script_tag(name:"creation_date", value:"2022-05-04 01:00:18 +0000 (Wed, 04 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-09 15:28:00 +0000 (Sat, 09 Apr 2022)");

  script_name("Debian: Security Advisory (DSA-5127)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5127");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5127");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5127 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2021-4197

Eric Biederman reported that incorrect permission checks in the cgroup process migration implementation can allow a local attacker to escalate privileges.

CVE-2022-0168

A NULL pointer dereference flaw was found in the CIFS client implementation which can allow a local attacker with CAP_SYS_ADMIN privileges to crash the system. The security impact is negligible as CAP_SYS_ADMIN inherently gives the ability to deny service.

CVE-2022-1016

David Bouman discovered a flaw in the netfilter subsystem where the nft_do_chain function did not initialize register data that nf_tables expressions can read from and write to. A local attacker can take advantage of this to read sensitive information.

CVE-2022-1048

Hu Jiahui discovered a race condition in the sound subsystem that can result in a use-after-free. A local user permitted to access a PCM sound device can take advantage of this flaw to crash the system or potentially for privilege escalation.

CVE-2022-1158

Qiuhao Li, Gaoning Pan, and Yongkang Jia discovered a bug in the KVM implementation for x86 processors. A local user with access to /dev/kvm could cause the MMU emulator to update page table entry flags at the wrong address. They could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2022-1195

Lin Ma discovered race conditions in the 6pack and mkiss hamradio drivers, which could lead to a use-after-free. A local user could exploit these to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2022-1198

Duoming Zhou discovered a race condition in the 6pack hamradio driver, which could lead to a use-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2022-1199, CVE-2022-1204, CVE-2022-1205 Duoming Zhou discovered race conditions in the AX.25 hamradio protocol, which could lead to a use-after-free or null pointer dereference. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2022-1353

The TCS Robot tool found an information leak in the PF_KEY subsystem. A local user can receive a netlink message when an IPsec daemon registers with the kernel, and this could include sensitive information.

CVE-2022-1516

A NULL pointer dereference flaw in the implementation of the X.25 set of standardized network protocols, which can result in denial of service.

This driver is not enabled in Debian's official kernel configurations.

CVE-2022-26490

Buffer overflows in the STMicroelectronics ST21NFCA core driver can result in denial of service or privilege escalation.

This driver is not enabled ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);