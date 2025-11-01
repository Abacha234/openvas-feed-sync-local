# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891823");
  script_cve_id("CVE-2019-10126", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11810", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-3846", "CVE-2019-5489");
  script_tag(name:"creation_date", value:"2019-06-18 02:00:44 +0000 (Tue, 18 Jun 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-28 12:20:00 +0000 (Thu, 28 Oct 2021)");

  script_name("Debian: Security Advisory (DLA-1823)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1823");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1823");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-1823 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2019-3846, CVE-2019-10126 huangwen reported multiple buffer overflows in the Marvell wifi (mwifiex) driver, which a local user could use to cause denial of service or the execution of arbitrary code.

CVE-2019-5489

Daniel Gruss, Erik Kraft, Trishita Tiwari, Michael Schwarz, Ari Trachtenberg, Jason Hennessey, Alex Ionescu, and Anders Fogh discovered that local users could use the mincore() system call to obtain sensitive information from other processes that access the same memory-mapped file.

CVE-2019-11477

Jonathan Looney reported that a specially crafted sequence of TCP selective acknowledgements (SACKs) allows a remotely triggerable kernel panic.

CVE-2019-11478

Jonathan Looney reported that a specially crafted sequence of TCP selective acknowledgements (SACKs) will fragment the TCP retransmission queue, allowing an attacker to cause excessive resource usage.

CVE-2019-11479

Jonathan Looney reported that an attacker could force the Linux kernel to segment its responses into multiple TCP segments, each of which contains only 8 bytes of data, drastically increasing the bandwidth required to deliver the same amount of data.

This update introduces a new sysctl value to control the minimal MSS (net.ipv4.tcp_min_snd_mss), which by default uses the formerly hard-coded value of 48. We recommend raising this to 512 unless you know that your network requires a lower value. (This value applies to Linux 3.16 only.)

CVE-2019-11810

It was discovered that the megaraid_sas driver did not correctly handle a failed memory allocation during initialisation, which could lead to a double-free. This might have some security impact, but it cannot be triggered by an unprivileged user.

CVE-2019-11833

It was discovered that the ext4 filesystem implementation writes uninitialised data from kernel memory to new extent blocks. A local user able to write to an ext4 filesystem and then read the filesystem image, for example using a removable drive, might be able to use this to obtain sensitive information.

CVE-2019-11884

It was discovered that the Bluetooth HIDP implementation did not ensure that new connection names were null-terminated. A local user with CAP_NET_ADMIN capability might be able to use this to obtain sensitive information from the kernel stack.

For Debian 8 Jessie, these problems have been fixed in version 3.16.68-2.

We recommend that you upgrade your linux packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);