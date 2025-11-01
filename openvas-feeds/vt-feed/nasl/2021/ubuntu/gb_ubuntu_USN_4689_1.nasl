# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844779");
  script_cve_id("CVE-2021-1052", "CVE-2021-1053", "CVE-2021-1056");
  script_tag(name:"creation_date", value:"2021-01-12 04:00:20 +0000 (Tue, 12 Jan 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-14 15:32:00 +0000 (Thu, 14 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-4689-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4689-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4689-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia-graphics-drivers-390, nvidia-graphics-drivers-450, nvidia-graphics-drivers-460' package(s) announced via the USN-4689-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the NVIDIA GPU display driver for the Linux kernel
contained a vulnerability that allowed user-mode clients to access legacy
privileged APIs. A local attacker could use this to cause a denial of
service or escalate privileges. (CVE-2021-1052)

It was discovered that the NVIDIA GPU display driver for the Linux kernel
did not properly validate a pointer received from userspace in some
situations. A local attacker could use this to cause a denial of service.
(CVE-2021-1053)

Xinyuan Lyu discovered that the NVIDIA GPU display driver for the Linux
kernel did not properly restrict device-level GPU isolation. A local
attacker could use this to cause a denial of service or possibly expose
sensitive information. (CVE-2021-1056)");

  script_tag(name:"affected", value:"'nvidia-graphics-drivers-390, nvidia-graphics-drivers-450, nvidia-graphics-drivers-460' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
