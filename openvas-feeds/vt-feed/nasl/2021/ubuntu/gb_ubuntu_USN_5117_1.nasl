# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845104");
  script_cve_id("CVE-2021-3739", "CVE-2021-3743", "CVE-2021-3753", "CVE-2021-3759");
  script_tag(name:"creation_date", value:"2021-10-21 01:01:20 +0000 (Thu, 21 Oct 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-11 15:24:00 +0000 (Fri, 11 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5117-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5117-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta-oem-5.13, linux-oem-5.13, linux-signed-oem-5.13' package(s) announced via the USN-5117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the btrfs file system in the Linux kernel did not
properly handle removing a non-existent device id. An attacker with
CAP_SYS_ADMIN could use this to cause a denial of service. (CVE-2021-3739)

It was discovered that the Qualcomm IPC Router protocol implementation in
the Linux kernel did not properly validate metadata in some situations. A
local attacker could use this to cause a denial of service (system crash)
or expose sensitive information. (CVE-2021-3743)

It was discovered that the virtual terminal (vt) device implementation in
the Linux kernel contained a race condition in its ioctl handling that led
to an out-of-bounds read vulnerability. A local attacker could possibly use
this to expose sensitive information. (CVE-2021-3753)

It was discovered that the Linux kernel did not properly account for the
memory usage of certain IPC objects. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2021-3759)");

  script_tag(name:"affected", value:"'linux-meta-oem-5.13, linux-oem-5.13, linux-signed-oem-5.13' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
