# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704073");
  script_cve_id("CVE-2017-1000407", "CVE-2017-1000410", "CVE-2017-16538", "CVE-2017-16644", "CVE-2017-16995", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-17558", "CVE-2017-17712", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-17807", "CVE-2017-17862", "CVE-2017-17863", "CVE-2017-17864", "CVE-2017-8824");
  script_tag(name:"creation_date", value:"2017-12-22 23:00:00 +0000 (Fri, 22 Dec 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:32:00 +0000 (Fri, 24 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-4073)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4073");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4073");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4073 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2017-8824

Mohamed Ghannam discovered that the DCCP implementation did not correctly manage resources when a socket is disconnected and reconnected, potentially leading to a use-after-free. A local user could use this for denial of service (crash or data corruption) or possibly for privilege escalation. On systems that do not already have the dccp module loaded, this can be mitigated by disabling it: echo >> /etc/modprobe.d/disable-dccp.conf install dccp false

CVE-2017-16538

Andrey Konovalov reported that the dvb-usb-lmedm04 media driver did not correctly handle some error conditions during initialisation. A physically present user with a specially designed USB device can use this to cause a denial of service (crash).

CVE-2017-16644

Andrey Konovalov reported that the hdpvr media driver did not correctly handle some error conditions during initialisation. A physically present user with a specially designed USB device can use this to cause a denial of service (crash).

CVE-2017-16995

Jann Horn discovered that the Extended BPF verifier did not correctly model the behaviour of 32-bit load instructions. A local user can use this for privilege escalation.

CVE-2017-17448

Kevin Cernekee discovered that the netfilter subsystem allowed users with the CAP_NET_ADMIN capability in any user namespace, not just the root namespace, to enable and disable connection tracking helpers. This could lead to denial of service, violation of network security policy, or have other impact.

CVE-2017-17449

Kevin Cernekee discovered that the netlink subsystem allowed users with the CAP_NET_ADMIN capability in any user namespace to monitor netlink traffic in all net namespaces, not just those owned by that user namespace. This could lead to exposure of sensitive information.

CVE-2017-17450

Kevin Cernekee discovered that the xt_osf module allowed users with the CAP_NET_ADMIN capability in any user namespace to modify the global OS fingerprint list.

CVE-2017-17558

Andrey Konovalov reported that USB core did not correctly handle some error conditions during initialisation. A physically present user with a specially designed USB device can use this to cause a denial of service (crash or memory corruption), or possibly for privilege escalation.

CVE-2017-17712

Mohamed Ghannam discovered a race condition in the IPv4 raw socket implementation. A local user could use this to obtain sensitive information from the kernel.

CVE-2017-17741

Dmitry Vyukov reported that the KVM implementation for x86 would over-read data from memory when emulating an MMIO write if the kvm_mmio tracepoint was enabled. A guest virtual machine might be able to use this to cause a denial of service (crash).

CVE-2017-17805

It was discovered that some implementations of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);