# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892586");
  script_cve_id("CVE-2019-19318", "CVE-2019-19813", "CVE-2019-19816", "CVE-2020-27815", "CVE-2020-27825", "CVE-2020-28374", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-26932", "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365", "CVE-2021-28038", "CVE-2021-3178", "CVE-2021-3347");
  script_tag(name:"creation_date", value:"2021-03-10 10:37:46 +0000 (Wed, 10 Mar 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)");

  script_name("Debian: Security Advisory (DLA-2586)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2586");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2586");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-2586 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2019-19318, CVE-2019-19813, CVE-2019-19816 Team bobfuzzer reported bugs in Btrfs that could lead to a use-after-free or heap buffer overflow, and could be triggered by crafted filesystem images. A user permitted to mount and access arbitrary filesystems could use these to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-27815

A flaw was reported in the JFS filesystem code allowing a local attacker with the ability to set extended attributes to cause a denial of service.

CVE-2020-27825

Adam pi3 Zabrocki reported a use-after-free flaw in the ftrace ring buffer resizing logic due to a race condition, which could result in denial of service or information leak.

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

CVE-2021-3178

Wu Yi reported an information leak in the NFSv3 server. When only a subdirectory of a filesystem volume is exported, an NFS client listing the exported directory would obtain a file handle to the parent directory, allowing it to access files that were not meant to be exported.

Even after this update, it is still possible for NFSv3 clients to guess valid file handles and access files outside an exported subdirectory, unless the subtree_check export option is enabled. It is recommended that you do not use that option but only export whole filesystem volumes.

CVE-2021-3347

It was discovered that PI futexes have a kernel stack use-after-free during fault handling. An unprivileged user could use this flaw to crash ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);