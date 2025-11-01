# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703791");
  script_cve_id("CVE-2016-6786", "CVE-2016-6787", "CVE-2016-8405", "CVE-2016-9191", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-2596", "CVE-2017-2618", "CVE-2017-5549", "CVE-2017-5551", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-6001", "CVE-2017-6074");
  script_tag(name:"creation_date", value:"2017-02-21 23:00:00 +0000 (Tue, 21 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 02:25:00 +0000 (Thu, 03 Nov 2022)");

  script_name("Debian: Security Advisory (DSA-3791)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3791");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3791");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3791 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or have other impacts.

CVE-2016-6786 / CVE-2016-6787 It was discovered that the performance events subsystem does not properly manage locks during certain migrations, allowing a local attacker to escalate privileges. This can be mitigated by disabling unprivileged use of performance events: sysctl kernel.perf_event_paranoid=3

CVE-2016-8405

Peter Pi of Trend Micro discovered that the frame buffer video subsystem does not properly check bounds while copying color maps to userspace, causing a heap buffer out-of-bounds read, leading to information disclosure.

CVE-2016-9191

CAI Qian discovered that reference counting is not properly handled within proc_sys_readdir in the sysctl implementation, allowing a local denial of service (system hang) or possibly privilege escalation.

CVE-2017-2583

Xiaohan Zhang reported that KVM for amd64 does not correctly emulate loading of a null stack selector. This can be used by a user in a guest VM for denial of service (on an Intel CPU) or to escalate privileges within the VM (on an AMD CPU).

CVE-2017-2584

Dmitry Vyukov reported that KVM for x86 does not correctly emulate memory access by the SGDT and SIDT instructions, which can result in a use-after-free and information leak.

CVE-2017-2596

Dmitry Vyukov reported that KVM leaks page references when emulating a VMON for a nested hypervisor. This can be used by a privileged user in a guest VM for denial of service or possibly to gain privileges in the host.

CVE-2017-2618

It was discovered that an off-by-one in the handling of SELinux attributes in /proc/pid/attr could result in local denial of service.

CVE-2017-5549

It was discovered that the KLSI KL5KUSB105 serial USB device driver could log the contents of uninitialised kernel memory, resulting in an information leak.

CVE-2017-5551

Jan Kara found that changing the POSIX ACL of a file on tmpfs never cleared its set-group-ID flag, which should be done if the user changing it is not a member of the group-owner. In some cases, this would allow the user-owner of an executable to gain the privileges of the group-owner.

CVE-2017-5897

Andrey Konovalov discovered an out-of-bounds read flaw in the ip6gre_err function in the IPv6 networking code.

CVE-2017-5970

Andrey Konovalov discovered a denial-of-service flaw in the IPv4 networking code. This can be triggered by a local or remote attacker if a local UDP or raw socket has the IP_RETOPTS option enabled.

CVE-2017-6001

Di Shen discovered a race condition between concurrent calls to the performance events subsystem, allowing a local attacker to escalate privileges. This flaw exists because of an incomplete fix of CVE-2016-6786. This can be mitigated by disabling unprivileged use of performance events: sysctl kernel.perf_event_paranoid=3

CVE-2017-6074

Andrey ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);