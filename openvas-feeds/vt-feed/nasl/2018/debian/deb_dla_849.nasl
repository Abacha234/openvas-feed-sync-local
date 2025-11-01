# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890849");
  script_cve_id("CVE-2016-9588", "CVE-2017-2636", "CVE-2017-5669", "CVE-2017-5986", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6348", "CVE-2017-6353");
  script_tag(name:"creation_date", value:"2018-01-11 23:00:00 +0000 (Thu, 11 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DLA-849)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-849");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-849");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-849 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or have other impacts.

CVE-2016-9588

Jim Mattson discovered that the KVM implementation for Intel x86 processors does not properly handle #BP and #OF exceptions in an L2 (nested) virtual machine. A local attacker in an L2 guest VM can take advantage of this flaw to cause a denial of service for the L1 guest VM.

CVE-2017-2636

Alexander Popov discovered a race condition flaw in the n_hdlc line discipline that can lead to a double free. A local unprivileged user can take advantage of this flaw for privilege escalation. On systems that do not already have the n_hdlc module loaded, this can be mitigated by disabling it: echo >> /etc/modprobe.d/disable-n_hdlc.conf install n_hdlc false

CVE-2017-5669

Gareth Evans reported that privileged users can map memory at address 0 through the shmat() system call. This could make it easier to exploit other kernel security vulnerabilities via a set-UID program.

CVE-2017-5986

Alexander Popov reported a race condition in the SCTP implementation that can be used by local users to cause a denial-of-service (crash). The initial fix for this was incorrect and introduced further security issues (CVE-2017-6353). This update includes a later fix that avoids those. On systems that do not already have the sctp module loaded, this can be mitigated by disabling it: echo >> /etc/modprobe.d/disable-sctp.conf install sctp false

CVE-2017-6214

Dmitry Vyukov reported a bug in the TCP implementation's handling of urgent data in the splice() system call. This can be used by a remote attacker for denial-of-service (hang) against applications that read from TCP sockets with splice().

CVE-2017-6345

Andrey Konovalov reported that the LLC type 2 implementation incorrectly assigns socket buffer ownership. This might be usable by a local user to cause a denial-of-service (memory corruption or crash) or privilege escalation. On systems that do not already have the llc2 module loaded, this can be mitigated by disabling it: echo >> /etc/modprobe.d/disable-llc2.conf install llc2 false

CVE-2017-6346

Dmitry Vyukov reported a race condition in the raw packet (af_packet) fanout feature. Local users with the CAP_NET_RAW capability (in any user namespace) can use this for denial-of-service and possibly for privilege escalation.

CVE-2017-6348

Dmitry Vyukov reported that the general queue implementation in the IrDA subsystem does not properly manage multiple locks, possibly allowing local users to cause a denial-of-service (deadlock) via crafted operations on IrDA devices.

For Debian 7 Wheezy, these problems have been fixed in version 3.2.86-1.

For Debian 8 Jessie, these problems have been fixed in version 3.16.39-1+deb8u2.

We recommend that you upgrade your linux packages.

Further information about Debian LTS security advisories, how to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);