# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705092");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-43976", "CVE-2022-0330", "CVE-2022-0435", "CVE-2022-0516", "CVE-2022-0847", "CVE-2022-22942", "CVE-2022-24448", "CVE-2022-24959", "CVE-2022-25258", "CVE-2022-25375");
  script_tag(name:"creation_date", value:"2022-03-08 02:00:11 +0000 (Tue, 08 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:00 +0000 (Thu, 07 Apr 2022)");

  script_name("Debian: Security Advisory (DSA-5092)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5092");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5092");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5092 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2021-43976

Zekun Shen and Brendan Dolan-Gavitt discovered a flaw in the mwifiex_usb_recv() function of the Marvell WiFi-Ex USB Driver. An attacker able to connect a crafted USB device can take advantage of this flaw to cause a denial of service.

CVE-2022-0330

Sushma Venkatesh Reddy discovered a missing GPU TLB flush in the i915 driver, resulting in denial of service or privilege escalation.

CVE-2022-0435

Samuel Page and Eric Dumazet reported a stack overflow in the networking module for the Transparent Inter-Process Communication (TIPC) protocol, resulting in denial of service or potentially the execution of arbitrary code.

CVE-2022-0516

It was discovered that an insufficient check in the KVM subsystem for s390x could allow unauthorized memory read or write access.

CVE-2022-0847

Max Kellermann discovered a flaw in the handling of pipe buffer flags. An attacker can take advantage of this flaw for local privilege escalation.

CVE-2022-22942

It was discovered that wrong file descriptor handling in the VMware Virtual GPU driver (vmwgfx) could result in information leak or privilege escalation.

CVE-2022-24448

Lyu Tao reported a flaw in the NFS implementation in the Linux kernel when handling requests to open a directory on a regular file, which could result in a information leak.

CVE-2022-24959

A memory leak was discovered in the yam_siocdevprivate() function of the YAM driver for AX.25, which could result in denial of service.

CVE-2022-25258

Szymon Heidrich reported the USB Gadget subsystem lacks certain validation of interface OS descriptor requests, resulting in memory corruption.

CVE-2022-25375

Szymon Heidrich reported that the RNDIS USB gadget lacks validation of the size of the RNDIS_MSG_SET command, resulting in information leak from kernel memory.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.92-2.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);