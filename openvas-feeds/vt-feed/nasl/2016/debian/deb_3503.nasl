# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703503");
  script_cve_id("CVE-2013-4312", "CVE-2015-8785", "CVE-2015-8812", "CVE-2015-8816", "CVE-2016-2069", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2550", "CVE-2016-2847");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:38 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 16:13:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Debian: Security Advisory (DSA-3503)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3503");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3503");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3503 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service, information leak or data loss.

CVE-2013-4312, CVE-2016-2847 Tetsuo Handa discovered that users can use pipes queued on local (Unix) sockets to allocate an unfair share of kernel memory, leading to denial-of-service (resource exhaustion). This issue was previously mitigated for the stable suite by limiting the total number of files queued by each user on local sockets. The new kernel version in both suites includes that mitigation plus limits on the total size of pipe buffers allocated for each user.

CVE-2015-7566

Ralf Spenneberg of OpenSource Security reported that the visor driver crashes when a specially crafted USB device without bulk-out endpoint is detected.

CVE-2015-8767

An SCTP denial-of-service was discovered which can be triggered by a local attacker during a heartbeat timeout event after the 4-way handshake.

CVE-2015-8785

It was discovered that local users permitted to write to a file on a FUSE filesystem could cause a denial of service (unkillable loop in the kernel).

CVE-2015-8812

A flaw was found in the iw_cxgb3 Infiniband driver. Whenever it could not send a packet because the network was congested, it would free the packet buffer but later attempt to send the packet again. This use-after-free could result in a denial of service (crash or hang), data loss or privilege escalation.

CVE-2015-8816

A use-after-free vulnerability was discovered in the USB hub driver. This may be used by a physically present user for privilege escalation.

CVE-2015-8830

Ben Hawkes of Google Project Zero reported that the AIO interface permitted reading or writing 2 GiB of data or more in a single chunk, which could lead to an integer overflow when applied to certain filesystems, socket or device types. The full security impact has not been evaluated.

CVE-2016-0723

A use-after-free vulnerability was discovered in the TIOCGETD ioctl. A local attacker could use this flaw for denial-of-service.

CVE-2016-0774

It was found that the fix for CVE-2015-1805 in kernel versions older than Linux 3.16 did not correctly handle the case of a partially failed atomic read. A local, unprivileged user could use this flaw to crash the system or leak kernel memory to user space.

CVE-2016-2069

Andy Lutomirski discovered a race condition in flushing of the TLB when switching tasks on an x86 system. On an SMP system this could possibly lead to a crash, information leak or privilege escalation.

CVE-2016-2384

Andrey Konovalov found that a crafted USB MIDI device with an invalid USB descriptor could trigger a double-free. This may be used by a physically present user for privilege escalation.

CVE-2016-2543

Dmitry Vyukov found that the core sound sequencer driver (snd-seq) lacked a necessary check for a null pointer, allowing a user with access to a sound sequencer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);