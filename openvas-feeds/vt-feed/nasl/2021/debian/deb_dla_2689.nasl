# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892689");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-26139", "CVE-2020-26147", "CVE-2020-26558", "CVE-2020-29374", "CVE-2020-36322", "CVE-2021-0129", "CVE-2021-0512", "CVE-2021-20292", "CVE-2021-23133", "CVE-2021-23134", "CVE-2021-28660", "CVE-2021-28688", "CVE-2021-28950", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-29154", "CVE-2021-29265", "CVE-2021-29647", "CVE-2021-29650", "CVE-2021-30002", "CVE-2021-31916", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-3428", "CVE-2021-3483", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-38208");
  script_tag(name:"creation_date", value:"2021-06-24 05:32:21 +0000 (Thu, 24 Jun 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-12 03:54:00 +0000 (Mon, 12 Sep 2022)");

  script_name("Debian: Security Advisory (DLA-2689)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2689");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2689");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-2689 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to the execution of arbitrary code, privilege escalation, denial of service, or information leaks.

This update is not yet available for the armel (ARM EABI soft-float) architecture.

CVE-2020-24586, CVE-2020-24587, CVE-2020-26147 Mathy Vanhoef discovered that many Wi-Fi implementations, including Linux's mac80211, did not correctly implement reassembly of fragmented packets. In some circumstances, an attacker within range of a network could exploit these flaws to forge arbitrary packets and/or to access sensitive data on that network.

CVE-2020-24588

Mathy Vanhoef discovered that most Wi-Fi implementations, including Linux's mac80211, did not authenticate the is aggregated packet header flag. An attacker within range of a network could exploit this to forge arbitrary packets on that network.

CVE-2020-25670, CVE-2020-25671, CVE-2021-23134 kiyin (Yin Liang ) of TenCent discovered several reference counting bugs in the NFC LLCP implementation which could lead to use-after-free. A local user could exploit these for denial of service (crash or memory corruption) or possibly for privilege escalation. Nadav Markus and Or Cohen of Palo Alto Networks discovered that the original fixes for these introduced a new bug that could result in use-after-free and double-free. This has also been fixed.

CVE-2020-25672

kiyin (Yin Liang ) of TenCent discovered a memory leak in the NFC LLCP implementation. A local user could exploit this for denial of service (memory exhaustion).

CVE-2020-26139

Mathy Vanhoef discovered that a bug in some Wi-Fi implementations, including Linux's mac80211. When operating in AP mode, they would forward EAPOL frames from one client to another while the sender was not yet authenticated. An attacker within range of a network could use this for denial of service or as an aid to exploiting other vulnerabilities.

CVE-2020-26558, CVE-2021-0129 Researchers at ANSSI discovered vulnerabilities in the Bluetooth Passkey authentication method, and in Linux's implementation of it. An attacker within range of two Bluetooth devices while they pair using Passkey authentication could exploit this to obtain the shared secret (Passkey) and then impersonate either of the devices to each other.

CVE-2020-29374

Jann Horn of Google reported a flaw in Linux's virtual memory management. A parent and child process initially share all their memory, but when either writes to a shared page, the page is duplicated and unshared (copy-on-write). However, in case an operation such as vmsplice() required the kernel to take an additional reference to a shared page, and a copy-on-write occurs during this operation, the kernel might have accessed the wrong process's memory. For some programs, this could lead to an information leak or data corruption.

CVE-2020-36322, CVE-2021-28950 The syzbot tool found that the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);