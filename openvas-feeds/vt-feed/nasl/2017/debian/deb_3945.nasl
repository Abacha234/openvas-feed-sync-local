# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703945");
  script_cve_id("CVE-2014-9940", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-10911", "CVE-2017-11176", "CVE-2017-7346", "CVE-2017-7482", "CVE-2017-7533", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-7889", "CVE-2017-9605");
  script_tag(name:"creation_date", value:"2017-08-16 22:00:00 +0000 (Wed, 16 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-14 21:12:00 +0000 (Tue, 14 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-3945)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3945");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3945");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3945 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2014-9940

A use-after-free flaw in the voltage and current regulator driver could allow a local user to cause a denial of service or potentially escalate privileges.

CVE-2017-7346

Li Qiang discovered that the DRM driver for VMware virtual GPUs does not properly check user-controlled values in the vmw_surface_define_ioctl() functions for upper limits. A local user can take advantage of this flaw to cause a denial of service.

CVE-2017-7482

Shi Lei discovered that RxRPC Kerberos 5 ticket handling code does not properly verify metadata, leading to information disclosure, denial of service or potentially execution of arbitrary code.

CVE-2017-7533

Fan Wu and Shixiong Zhao discovered a race condition between inotify events and VFS rename operations allowing an unprivileged local attacker to cause a denial of service or escalate privileges.

CVE-2017-7541

A buffer overflow flaw in the Broadcom IEEE802.11n PCIe SoftMAC WLAN driver could allow a local user to cause kernel memory corruption, leading to a denial of service or potentially privilege escalation.

CVE-2017-7542

An integer overflow vulnerability in the ip6_find_1stfragopt() function was found allowing a local attacker with privileges to open raw sockets to cause a denial of service.

CVE-2017-7889

Tommi Rantala and Brad Spengler reported that the mm subsystem does not properly enforce the CONFIG_STRICT_DEVMEM protection mechanism, allowing a local attacker with access to /dev/mem to obtain sensitive information or potentially execute arbitrary code.

CVE-2017-9605

Murray McAllister discovered that the DRM driver for VMware virtual GPUs does not properly initialize memory, potentially allowing a local attacker to obtain sensitive information from uninitialized kernel memory via a crafted ioctl call.

CVE-2017-10911

/ XSA-216

Anthony Perard of Citrix discovered an information leak flaw in Xen blkif response handling, allowing a malicious unprivileged guest to obtain sensitive information from the host or other guests.

CVE-2017-11176

It was discovered that the mq_notify() function does not set the sock pointer to NULL upon entry into the retry logic. An attacker can take advantage of this flaw during a userspace close of a Netlink socket to cause a denial of service or potentially cause other impact.

CVE-2017-1000363

Roee Hay reported that the lp driver does not properly bounds-check passed arguments, allowing a local attacker with write access to the kernel command line arguments to execute arbitrary code.

CVE-2017-1000365

It was discovered that argument and environment pointers are not taken properly into account to the imposed size restrictions on arguments and environmental strings passed through RLIMIT_STACK/RLIMIT_INFINITY. A local attacker can take ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);