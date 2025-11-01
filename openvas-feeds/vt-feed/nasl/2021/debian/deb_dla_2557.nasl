# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892557");
  script_cve_id("CVE-2020-27815", "CVE-2020-27825", "CVE-2020-27830", "CVE-2020-28374", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158", "CVE-2021-20177", "CVE-2021-3347");
  script_tag(name:"creation_date", value:"2021-02-14 04:00:31 +0000 (Sun, 14 Feb 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)");

  script_name("Debian: Security Advisory (DLA-2557)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2557");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2557");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux-4.19");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.19' package(s) announced via the DLA-2557 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2020-27815

A flaw was reported in the JFS filesystem code allowing a local attacker with the ability to set extended attributes to cause a denial of service.

CVE-2020-27825

Adam pi3 Zabrocki reported a use-after-free flaw in the ftrace ring buffer resizing logic due to a race condition, which could result in denial of service or information leak.

CVE-2020-27830

Shisong Qin reported a NULL pointer dereference flaw in the Speakup screen reader core driver.

CVE-2020-28374

David Disseldorp discovered that the LIO SCSI target implementation performed insufficient checking in certain XCOPY requests. An attacker with access to a LUN and knowledge of Unit Serial Number assignments can take advantage of this flaw to read and write to any LIO backstore, regardless of the SCSI transport settings.

CVE-2020-29568 (XSA-349) Michael Kurth and Pawel Wieczorkiewicz reported that frontends can trigger OOM in backends by updating a watched path.

CVE-2020-29569 (XSA-350) Olivier Benjamin and Pawel Wieczorkiewicz reported a use-after-free flaw which can be triggered by a block frontend in Linux blkback. A misbehaving guest can trigger a dom0 crash by continuously connecting / disconnecting a block frontend.

CVE-2020-29660

Jann Horn reported a locking inconsistency issue in the tty subsystem which may allow a local attacker to mount a read-after-free attack against TIOCGSID.

CVE-2020-29661

Jann Horn reported a locking issue in the tty subsystem which can result in a use-after-free. A local attacker can take advantage of this flaw for memory corruption or privilege escalation.

CVE-2020-36158

A buffer overflow flaw was discovered in the mwifiex WiFi driver which could result in denial of service or the execution of arbitrary code via a long SSID value.

CVE-2021-3347

It was discovered that PI futexes have a kernel stack use-after-free during fault handling. An unprivileged user could use this flaw to crash the kernel (resulting in denial of service) or for privilege escalation.

CVE-2021-20177

A flaw was discovered in the Linux implementation of string matching within a packet. A privileged user (with root or CAP_NET_ADMIN) can take advantage of this flaw to cause a kernel panic when inserting iptables rules.

For Debian 9 stretch, these problems have been fixed in version 4.19.171-2~deb9u1.

We recommend that you upgrade your linux-4.19 packages.

For the detailed security status of linux-4.19 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'linux-4.19' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);