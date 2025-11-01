# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68992");
  script_cve_id("CVE-2010-0435", "CVE-2010-3699", "CVE-2010-4158", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4242", "CVE-2010-4243", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4649", "CVE-2010-4656", "CVE-2010-4668", "CVE-2011-0521");
  script_tag(name:"creation_date", value:"2011-03-07 15:04:02 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 14:39:00 +0000 (Wed, 12 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-2153)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2153");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2153");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6, user-mode-linux' package(s) announced via the DSA-2153 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leak. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-0435

Gleb Napatov reported an issue in the KVM subsystem that allows virtual machines to cause a denial of service of the host machine by executing mov to/from DR instructions.

CVE-2010-3699

Keir Fraser provided a fix for an issue in the Xen subsystem. A guest can cause a denial of service on the host by retaining a leaked reference to a device. This can result in a zombie domain, xenwatch process hangs, and xm command failures.

CVE-2010-4158

Dan Rosenberg discovered an issue in the socket filters subsystem, allowing local unprivileged users to obtain the contents of sensitive kernel memory.

CVE-2010-4162

Dan Rosenberg discovered an overflow issue in the block I/O subsystem that allows local users to map large numbers of pages, resulting in a denial of service due to invocation of the out of memory killer.

CVE-2010-4163

Dan Rosenberg discovered an issue in the block I/O subsystem. Due to improper validation of iov segments, local users can trigger a kernel panic resulting in a denial of service.

CVE-2010-4242

Alan Cox reported an issue in the Bluetooth subsystem. Local users with sufficient permission to access HCI UART devices can cause a denial of service (NULL pointer dereference) due to a missing check for an existing tty write operation.

CVE-2010-4243

Brad Spengler reported a denial-of-service issue in the kernel memory accounting system. By passing large argv/envp values to exec, local users can cause the out of memory killer to kill processes owned by other users.

CVE-2010-4248

Oleg Nesterov reported an issue in the POSIX CPU timers subsystem. Local users can cause a denial of service (Oops) due to incorrect assumptions about thread group leader behavior.

CVE-2010-4249

Vegard Nossum reported an issue with the UNIX socket garbage collector. Local users can consume all of LOWMEM and decrease system performance by overloading the system with inflight sockets.

CVE-2010-4258

Nelson Elhage reported an issue in Linux oops handling. Local users may be able to obtain elevated privileges if they are able to trigger an oops with a process' fs set to KERNEL_DS.

CVE-2010-4342

Nelson Elhage reported an issue in the Econet protocol. Remote attackers can cause a denial of service by sending an Acorn Universal Networking packet over UDP.

CVE-2010-4346

Tavis Ormandy discovered an issue in the install_special_mapping routine which allows local users to bypass the mmap_min_addr security restriction. Combined with an otherwise low severity local denial of service vulnerability (NULL pointer dereference), a local user could obtain elevated privileges.

CVE-2010-4526

Eugene Teo reported a race condition in the Linux SCTP ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-2.6, user-mode-linux' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);