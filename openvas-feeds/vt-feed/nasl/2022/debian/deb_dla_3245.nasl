# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893245");
  script_cve_id("CVE-2022-20369", "CVE-2022-2978", "CVE-2022-29901", "CVE-2022-3521", "CVE-2022-3524", "CVE-2022-3564", "CVE-2022-3565", "CVE-2022-3594", "CVE-2022-3621", "CVE-2022-3628", "CVE-2022-3640", "CVE-2022-3643", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-40768", "CVE-2022-41849", "CVE-2022-41850", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-43750", "CVE-2022-4378");
  script_tag(name:"creation_date", value:"2022-12-24 02:00:26 +0000 (Sat, 24 Dec 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 15:27:00 +0000 (Mon, 12 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3245)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3245");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3245");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/return-stack-buffer-underflow.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-3245 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2022-2978

butt3rflyh4ck, Hao Sun, and Jiacheng Xu reported a flaw in the nilfs2 filesystem driver which can lead to a use-after-free. A local use might be able to exploit this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2022-3521

The syzbot tool found a race condition in the KCM subsystem which could lead to a crash.

This subsystem is not enabled in Debian's official kernel configurations.

CVE-2022-3524

The syzbot tool found a race condition in the IPv6 stack which could lead to a memory leak. A local user could exploit this to cause a denial of service (memory exhaustion).

CVE-2022-3564

A flaw was discovered in the Bluetooth L2CAP subsystem which would lead to a use-after-free. This might be exploitable to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2022-3565

A flaw was discovered in the mISDN driver which would lead to a use-after-free. This might be exploitable to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2022-3594

Andrew Gaul reported that the r8152 Ethernet driver would log excessive numbers of messages in response to network errors. A remote attacker could possibly exploit this to cause a denial of service (resource exhaustion).

CVE-2022-3621, CVE-2022-3646 The syzbot tool found flaws in the nilfs2 filesystem driver which can lead to a null pointer dereference or memory leak. A user permitted to mount arbitrary filesystem images could use these to cause a denial of service (crash or resource exhaustion).

CVE-2022-3628

Dokyung Song, Jisoo Jang, and Minsuk Kang reported a potential heap-based buffer overflow in the brcmfmac Wi-Fi driver. A user able to connect a malicious USB device could exploit this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2022-3640

A flaw was discovered in the Bluetooth L2CAP subsystem which would lead to a use-after-free. This might be exploitable to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2022-3643 (XSA-423) A flaw was discovered in the Xen network backend driver that would result in it generating malformed packet buffers. If these packets were forwarded to certain other network devices, a Xen guest could exploit this to cause a denial of service (crash or device reset).

CVE-2022-3649

The syzbot tool found flaws in the nilfs2 filesystem driver which can lead to a use-after-free. A user permitted to mount arbitrary filesystem images could use these to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2022-4378

Kyle Zeng found a flaw in procfs that would ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);