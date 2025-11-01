# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845402");
  script_cve_id("CVE-2022-1836", "CVE-2022-1966", "CVE-2022-1972", "CVE-2022-21499");
  script_tag(name:"creation_date", value:"2022-06-09 01:00:48 +0000 (Thu, 09 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-17 14:55:00 +0000 (Fri, 17 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-5470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5470-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5470-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta-oem-5.14, linux-oem-5.14, linux-signed-oem-5.14' package(s) announced via the USN-5470-1 advisory.");

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

Minh Yuan discovered that the floppy driver in the Linux kernel contained a
race condition in some situations, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-1836)

Ziming Zhang discovered that the netfilter subsystem in the Linux kernel
did not properly validate sets with multiple ranged fields. A local
attacker could use this to cause a denial of service or execute arbitrary
code. (CVE-2022-1972)");

  script_tag(name:"affected", value:"'linux-meta-oem-5.14, linux-oem-5.14, linux-signed-oem-5.14' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
