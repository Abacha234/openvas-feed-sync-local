# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845070");
  script_cve_id("CVE-2021-22543", "CVE-2021-3612");
  script_tag(name:"creation_date", value:"2021-09-23 01:00:34 +0000 (Thu, 23 Sep 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-13 18:30:00 +0000 (Tue, 13 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-5071-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5071-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5071-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta-raspi, linux-meta-raspi-5.4, linux-raspi, linux-raspi-5.4' package(s) announced via the USN-5071-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the KVM hypervisor implementation in the Linux
kernel did not properly perform reference counting in some situations,
leading to a use-after-free vulnerability. An attacker who could start and
control a VM could possibly use this to expose sensitive information or
execute arbitrary code. (CVE-2021-22543)

Murray McAllister discovered that the joystick device interface in the
Linux kernel did not properly validate data passed via an ioctl(). A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code on systems with a joystick device
registered. (CVE-2021-3612)");

  script_tag(name:"affected", value:"'linux-meta-raspi, linux-meta-raspi-5.4, linux-raspi, linux-raspi-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
