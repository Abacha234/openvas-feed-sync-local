# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704082");
  script_cve_id("CVE-2017-1000407", "CVE-2017-1000410", "CVE-2017-15868", "CVE-2017-16538", "CVE-2017-16939", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-17558", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-17807", "CVE-2017-5754", "CVE-2017-8824");
  script_tag(name:"creation_date", value:"2018-01-08 23:00:00 +0000 (Mon, 08 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:32:00 +0000 (Fri, 24 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-4082)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4082");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4082");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4082 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2017-5754

Multiple researchers have discovered a vulnerability in Intel processors, enabling an attacker controlling an unprivileged process to read memory from arbitrary addresses, including from the kernel and all other processes running on the system.

This specific attack has been named Meltdown and is addressed in the Linux kernel for the Intel x86-64 architecture by a patch set named Kernel Page Table Isolation, enforcing a near complete separation of the kernel and userspace address maps and preventing the attack. This solution might have a performance impact, and can be disabled at boot time by passing pti=off to the kernel command line.

CVE-2017-8824

Mohamed Ghannam discovered that the DCCP implementation did not correctly manage resources when a socket is disconnected and reconnected, potentially leading to a use-after-free. A local user could use this for denial of service (crash or data corruption) or possibly for privilege escalation. On systems that do not already have the dccp module loaded, this can be mitigated by disabling it: echo >> /etc/modprobe.d/disable-dccp.conf install dccp false

CVE-2017-15868

Al Viro found that the Bluebooth Network Encapsulation Protocol (BNEP) implementation did not validate the type of the second socket passed to the BNEPCONNADD ioctl(), which could lead to memory corruption. A local user with the CAP_NET_ADMIN capability can use this for denial of service (crash or data corruption) or possibly for privilege escalation.

CVE-2017-16538

Andrey Konovalov reported that the dvb-usb-lmedm04 media driver did not correctly handle some error conditions during initialisation. A physically present user with a specially designed USB device can use this to cause a denial of service (crash).

CVE-2017-16939

Mohamed Ghannam reported (through Beyond Security's SecuriTeam Secure Disclosure program) that the IPsec (xfrm) implementation did not correctly handle some failure cases when dumping policy information through netlink. A local user with the CAP_NET_ADMIN capability can use this for denial of service (crash or data corruption) or possibly for privilege escalation.

CVE-2017-17448

Kevin Cernekee discovered that the netfilter subsystem allowed users with the CAP_NET_ADMIN capability in any user namespace, not just the root namespace, to enable and disable connection tracking helpers. This could lead to denial of service, violation of network security policy, or have other impact.

CVE-2017-17449

Kevin Cernekee discovered that the netlink subsystem allowed users with the CAP_NET_ADMIN capability in any user namespace to monitor netlink traffic in all net namespaces, not just those owned by that user namespace. This could lead to exposure of sensitive ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);