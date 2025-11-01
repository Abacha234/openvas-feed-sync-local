# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892713");
  script_cve_id("CVE-2021-21781", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-3609");
  script_tag(name:"creation_date", value:"2021-07-21 03:00:18 +0000 (Wed, 21 Jul 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-29 17:46:00 +0000 (Thu, 29 Jul 2021)");

  script_name("Debian: Security Advisory (DLA-2713)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2713");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2713-2");
  script_xref(name:"URL", value:"https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-2713 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2021-3609

Norbert Slusarek reported a race condition vulnerability in the CAN BCM networking protocol, allowing a local attacker to escalate privileges.

CVE-2021-21781

'Lilith >_>' of Cisco Talos discovered that the Arm initialisation code does not fully initialise the sigpage that is mapped into user-space processes to support signal handling. This could result in leaking sensitive information, particularly when the system is rebooted.

CVE-2021-33909

The Qualys Research Labs discovered a size_t-to-int conversion vulnerability in the Linux kernel's filesystem layer. An unprivileged local attacker able to create, mount, and then delete a deep directory structure whose total path length exceeds 1GB, can take advantage of this flaw for privilege escalation.

Details can be found in the Qualys advisory at [link moved to references]

CVE-2021-34693

Norbert Slusarek discovered an information leak in the CAN BCM networking protocol. A local attacker can take advantage of this flaw to obtain sensitive information from kernel stack memory.

For Debian 9 stretch, these problems have been fixed in version 4.9.272-2. This additionally fixes a regression in the previous update (#990072) that affected LXC.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);