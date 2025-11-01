# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844980");
  script_cve_id("CVE-2020-14372", "CVE-2020-25632", "CVE-2020-27749", "CVE-2020-27779", "CVE-2021-20225", "CVE-2021-20233");
  script_tag(name:"creation_date", value:"2021-06-19 03:00:23 +0000 (Sat, 19 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-4992-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4992-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4992-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/GRUB2SecureBootBypass2021");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2-signed, grub2-unsigned' package(s) announced via the USN-4992-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mate Kukri discovered that the acpi command in GRUB 2 allowed privileged
users to load crafted ACPI tables when secure boot is enabled. An attacker
could use this to bypass UEFI Secure Boot restrictions. (CVE-2020-14372)

Chris Coulson discovered that the rmmod command in GRUB 2 contained a use-
after-free vulnerability. A local attacker could use this to execute
arbitrary code and bypass UEFI Secure Boot restrictions. (CVE-2020-25632)

Chris Coulson discovered that a buffer overflow existed in the command line
parser in GRUB 2. A local attacker could use this to execute arbitrary code
and bypass UEFI Secure Boot restrictions. (CVE-2020-27749)

It was discovered that the cutmem command in GRUB 2 did not honor secure
boot locking. A local attacker could use this to execute arbitrary code and
bypass UEFI Secure Boot restrictions. (CVE-2020-27779)

It was discovered that the option parser in GRUB 2 contained a heap
overflow vulnerability. A local attacker could use this to execute
arbitrary code and bypass UEFI Secure Boot restrictions. (CVE-2021-20225)

It was discovered that the menu rendering implementation in GRUB 2 did not
properly calculate the amount of memory needed in some situations, leading
to out-of-bounds writes. A local attacker could use this to execute
arbitrary code and bypass UEFI Secure Boot restrictions. (CVE-2021-20233)");

  script_tag(name:"affected", value:"'grub2-signed, grub2-unsigned' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
