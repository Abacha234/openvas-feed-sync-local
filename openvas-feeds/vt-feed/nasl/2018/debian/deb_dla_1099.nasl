# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891099");
  script_cve_id("CVE-2017-1000111", "CVE-2017-1000251", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-10911", "CVE-2017-11176", "CVE-2017-11600", "CVE-2017-12134", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-14156", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-7482", "CVE-2017-7542", "CVE-2017-7889");
  script_tag(name:"creation_date", value:"2018-02-06 23:00:00 +0000 (Tue, 06 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-03 19:00:00 +0000 (Wed, 03 Jun 2020)");

  script_name("Debian: Security Advisory (DLA-1099)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1099");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1099");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-1099 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2017-7482

Shi Lei discovered that RxRPC Kerberos 5 ticket handling code does not properly verify metadata, leading to information disclosure, denial of service or potentially execution of arbitrary code.

CVE-2017-7542

An integer overflow vulnerability in the ip6_find_1stfragopt() function was found allowing a local attacker with privileges to open raw sockets to cause a denial of service.

CVE-2017-7889

Tommi Rantala and Brad Spengler reported that the mm subsystem does not properly enforce the CONFIG_STRICT_DEVMEM protection mechanism, allowing a local attacker with access to /dev/mem to obtain sensitive information or potentially execute arbitrary code.

CVE-2017-10661

Dmitry Vyukov of Google reported that the timerfd facility does not properly handle certain concurrent operations on a single file descriptor. This allows a local attacker to cause a denial of service or potentially to execute arbitrary code.

CVE-2017-10911 / XSA-216 Anthony Perard of Citrix discovered an information leak flaw in Xen blkif response handling, allowing a malicious unprivileged guest to obtain sensitive information from the host or other guests.

CVE-2017-11176

It was discovered that the mq_notify() function does not set the sock pointer to NULL upon entry into the retry logic. An attacker can take advantage of this flaw during a userspace close of a Netlink socket to cause a denial of service or potentially cause other impact.

CVE-2017-11600

bo Zhang reported that the xfrm subsystem does not properly validate one of the parameters to a netlink message. Local users with the CAP_NET_ADMIN capability can use this to cause a denial of service or potentially to execute arbitrary code.

CVE-2017-12134 / #866511 / XSA-229 Jan H. Schonherr of Amazon discovered that when Linux is running in a Xen PV domain on an x86 system, it may incorrectly merge block I/O requests. A buggy or malicious guest may trigger this bug in dom0 or a PV driver domain, causing a denial of service or potentially execution of arbitrary code. This issue can be mitigated by disabling merges on the underlying back-end block devices, e.g.: echo 2 > /sys/block/nvme0n1/queue/nomerges

CVE-2017-12153

bo Zhang reported that the cfg80211 (wifi) subsystem does not properly validate the parameters to a netlink message. Local users with the CAP_NET_ADMIN capability on a system with a wifi device can use this to cause a denial of service.

CVE-2017-12154

Jim Mattson of Google reported that the KVM implementation for Intel x86 processors did not correctly handle certain nested hypervisor configurations. A malicious guest (or nested guest in a suitable L1 hypervisor) could use this for denial of service.

CVE-2017-14106

Andrey Konovalov of Google reported that a specific ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);