# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845401");
  script_cve_id("CVE-2022-1012", "CVE-2022-1205", "CVE-2022-1734", "CVE-2022-1836", "CVE-2022-1966", "CVE-2022-1972", "CVE-2022-21499", "CVE-2022-29968");
  script_tag(name:"creation_date", value:"2022-06-09 01:00:43 +0000 (Thu, 09 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-11 13:36:00 +0000 (Thu, 11 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-5471-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5471-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5471-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta-oem-5.17, linux-oem-5.17, linux-signed-oem-5.17' package(s) announced via the USN-5471-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not properly restrict access to
the kernel debugger when booted in secure boot environments. A privileged
attacker could use this to bypass UEFI Secure Boot restrictions.
(CVE-2022-21499)

Aaron Adams discovered that the netfilter subsystem in the Linux kernel did
not properly handle the removal of stateful expressions in some situations,
leading to a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or execute arbitrary code.
(CVE-2022-1966)

It was discovered that the IP implementation in the Linux kernel did not
provide sufficient randomization when calculating port offsets. An attacker
could possibly use this to expose sensitive information. (CVE-2022-1012)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel, leading to use-after-free
vulnerabilities. A local attacker could possibly use this to cause a denial
of service (system crash). (CVE-2022-1205)

It was discovered that the Marvell NFC device driver implementation in the
Linux kernel did not properly perform memory cleanup operations in some
situations, leading to a use-after-free vulnerability. A local attacker
could possibly use this to cause a denial of service (system crash) or
execute arbitrary code. (CVE-2022-1734)

Minh Yuan discovered that the floppy driver in the Linux kernel contained a
race condition in some situations, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-1836)

Ziming Zhang discovered that the netfilter subsystem in the Linux kernel
did not properly validate sets with multiple ranged fields. A local
attacker could use this to cause a denial of service or execute arbitrary
code. (CVE-2022-1972)

Joseph Ravichandran and Michael Wang discovered that the io_uring subsystem
in the Linux kernel did not properly initialize data in some situations. A
local attacker could use this to expose sensitive information (kernel
memory). (CVE-2022-29968)");

  script_tag(name:"affected", value:"'linux-meta-oem-5.17, linux-oem-5.17, linux-signed-oem-5.17' package(s) on Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
