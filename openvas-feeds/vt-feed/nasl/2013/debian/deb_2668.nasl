# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702668");
  script_cve_id("CVE-2012-2121", "CVE-2012-3552", "CVE-2012-4461", "CVE-2012-4508", "CVE-2012-6537", "CVE-2012-6539", "CVE-2012-6540", "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6548", "CVE-2012-6549", "CVE-2013-0349", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1774", "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1798", "CVE-2013-1826", "CVE-2013-1860", "CVE-2013-1928", "CVE-2013-1929", "CVE-2013-2015", "CVE-2013-2634", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3234", "CVE-2013-3235");
  script_tag(name:"creation_date", value:"2013-05-13 22:00:00 +0000 (Mon, 13 May 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 11:33:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Debian: Security Advisory (DSA-2668)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2668");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2668");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2668 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service, information leak or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-2121

Benjamin Herrenschmidt and Jason Baron discovered issues with the IOMMU mapping of memory slots used in KVM device assignment. Local users with the ability to assign devices could cause a denial of service due to a memory page leak.

CVE-2012-3552

Hafid Lin reported an issue in the IP networking subsystem. A remote user can cause a denial of service (system crash) on servers running applications that set options on sockets which are actively being processed.

CVE-2012-4461

Jon Howell reported a denial of service issue in the KVM subsystem. On systems that do not support the XSAVE feature, local users with access to the /dev/kvm interface can cause a system crash.

CVE-2012-4508

Dmitry Monakhov and Theodore Ts'o reported a race condition in the ext4 filesystem. Local users could gain access to sensitive kernel memory.

CVE-2012-6537

Mathias Krause discovered information leak issues in the Transformation user configuration interface. Local users with the CAP_NET_ADMIN capability can gain access to sensitive kernel memory.

CVE-2012-6539

Mathias Krause discovered an issue in the networking subsystem. Local users on 64-bit systems can gain access to sensitive kernel memory.

CVE-2012-6540

Mathias Krause discovered an issue in the Linux virtual server subsystem. Local users can gain access to sensitive kernel memory. Note: this issue does not affect Debian provided kernels, but may affect custom kernels built from Debian's linux-source-2.6.32 package.

CVE-2012-6542

Mathias Krause discovered an issue in the LLC protocol support code. Local users can gain access to sensitive kernel memory.

CVE-2012-6544

Mathias Krause discovered issues in the Bluetooth subsystem. Local users can gain access to sensitive kernel memory.

CVE-2012-6545

Mathias Krause discovered issues in the Bluetooth RFCOMM protocol support. Local users can gain access to sensitive kernel memory.

CVE-2012-6546

Mathias Krause discovered issues in the ATM networking support. Local users can gain access to sensitive kernel memory.

CVE-2012-6548

Mathias Krause discovered an issue in the UDF file system support. Local users can obtain access to sensitive kernel memory.

CVE-2012-6549

Mathias Krause discovered an issue in the isofs file system support. Local users can obtain access to sensitive kernel memory.

CVE-2013-0349

Anderson Lizardo discovered an issue in the Bluetooth Human Interface Device Protocol (HIDP) stack. Local users can obtain access to sensitive kernel memory.

CVE-2013-0914

Emese Revfy discovered an issue in the signal implementation. Local users may be able to bypass the address space layout randomization (ASLR) facility due to a leaking of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);