# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845243");
  script_cve_id("CVE-2021-3640", "CVE-2021-3752", "CVE-2021-42739");
  script_tag(name:"creation_date", value:"2022-02-17 07:17:35 +0000 (Thu, 17 Feb 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-28 19:47:00 +0000 (Mon, 28 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5267-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5267-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5267-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta-raspi, linux-meta-raspi-5.4, linux-raspi, linux-raspi-5.4' package(s) announced via the USN-5267-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5267-1 fixed vulnerabilities in the Linux kernel. This update
provides the corresponding updates for the Linux kernel for Raspberry
Pi devices.

Original advisory details:

 It was discovered that the Bluetooth subsystem in the Linux kernel
 contained a use-after-free vulnerability. A local attacker could use this
 to cause a denial of service (system crash) or possibly execute arbitrary
 code. (CVE-2021-3640)

 Likang Luo discovered that a race condition existed in the Bluetooth
 subsystem of the Linux kernel, leading to a use-after-free vulnerability. A
 local attacker could use this to cause a denial of service (system crash)
 or possibly execute arbitrary code. (CVE-2021-3752)

 Luo Likang discovered that the FireDTV Firewire driver in the Linux kernel
 did not properly perform bounds checking in some situations. A local
 attacker could use this to cause a denial of service (system crash) or
 possibly execute arbitrary code. (CVE-2021-42739)");

  script_tag(name:"affected", value:"'linux-meta-raspi, linux-meta-raspi-5.4, linux-raspi, linux-raspi-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
