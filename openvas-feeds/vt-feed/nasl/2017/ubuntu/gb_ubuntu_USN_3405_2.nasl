# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843298");
  script_cve_id("CVE-2015-7837", "CVE-2017-11176", "CVE-2017-7495", "CVE-2017-7541");
  script_tag(name:"creation_date", value:"2017-08-29 06:06:11 +0000 (Tue, 29 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-08 02:29:00 +0000 (Fri, 08 Dec 2017)");

  script_name("Ubuntu: Security Advisory (USN-3405-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3405-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3405-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-xenial, linux-meta-lts-xenial' package(s) announced via the USN-3405-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3405-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

It was discovered that a use-after-free vulnerability existed in the POSIX
message queue implementation in the Linux kernel. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-11176)

Huang Weller discovered that the ext4 filesystem implementation in the
Linux kernel mishandled a needs-flushing-before-commit list. A local
attacker could use this to expose sensitive information. (CVE-2017-7495)

It was discovered that a buffer overflow existed in the Broadcom FullMAC
WLAN driver in the Linux kernel. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2017-7541)

It was discovered that the Linux kernel did not honor the UEFI secure boot
mode when performing a kexec operation. A local attacker could use this to
bypass secure boot restrictions. (CVE-2015-7837)");

  script_tag(name:"affected", value:"'linux-lts-xenial, linux-meta-lts-xenial' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
