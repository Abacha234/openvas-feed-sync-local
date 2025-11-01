# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705191");
  script_cve_id("CVE-2021-33655", "CVE-2022-2318", "CVE-2022-26365", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33743", "CVE-2022-33744", "CVE-2022-34918");
  script_tag(name:"creation_date", value:"2022-07-28 01:00:21 +0000 (Thu, 28 Jul 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 14:00:00 +0000 (Wed, 13 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-5191)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5191");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5191");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5191 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to privilege escalation, denial of service or information leaks:

CVE-2021-33655

A user with access to a framebuffer console driver could cause a memory out-of-bounds write via the FBIOPUT_VSCREENINFO ioctl.

CVE-2022-2318

A use-after-free in the Amateur Radio X.25 PLP (Rose) support may result in denial of service.

CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742 Roger Pau Monne discovered that Xen block and network PV device frontends don't zero out memory regions before sharing them with the backend, which may result in information disclosure. Additionally it was discovered that the granularity of the grant table doesn't permit sharing less than a 4k page, which may also result in information disclosure.

CVE-2022-33743

Jan Beulich discovered that incorrect memory handling in the Xen network backend may lead to denial of service.

CVE-2022-33744

Oleksandr Tyshchenko discovered that ARM Xen guests can cause a denial of service to the Dom0 via paravirtual devices.

CVE-2022-34918

Arthur Mongodin discovered a heap buffer overflow in the Netfilter subsystem which may result in local privilege escalation.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.127-2.

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