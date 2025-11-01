# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844316");
  script_cve_id("CVE-2019-15099", "CVE-2019-15291", "CVE-2019-18683", "CVE-2019-18885", "CVE-2019-19050", "CVE-2019-19062", "CVE-2019-19071", "CVE-2019-19077", "CVE-2019-19078", "CVE-2019-19079", "CVE-2019-19082", "CVE-2019-19227", "CVE-2019-19252", "CVE-2019-19332", "CVE-2019-19767");
  script_tag(name:"creation_date", value:"2020-01-29 04:00:31 +0000 (Wed, 29 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4258-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4258-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4258-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-5.0, linux-gcp, linux-gke-5.0, linux-meta-aws-5.0, linux-meta-gcp, linux-meta-gke-5.0, linux-meta-oracle-5.0, linux-oracle-5.0, linux-signed-gcp, linux-signed-gke-5.0, linux-signed-oracle-5.0' package(s) announced via the USN-4258-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Atheros 802.11ac wireless USB device driver in
the Linux kernel did not properly validate device metadata. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2019-15099)

It was discovered that a race condition existed in the Virtual Video Test
Driver in the Linux kernel. An attacker with write access to /dev/video0 on
a system with the vivid module loaded could possibly use this to gain
administrative privileges. (CVE-2019-18683)

It was discovered that the btrfs file system in the Linux kernel did not
properly validate metadata, leading to a NULL pointer dereference. An
attacker could use this to specially craft a file system image that, when
mounted, could cause a denial of service (system crash). (CVE-2019-18885)

It was discovered that the crypto subsystem in the Linux kernel did not
properly deallocate memory in certain error conditions. A local attacker
could use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19050, CVE-2019-19062)

It was discovered that the RSI 91x WLAN device driver in the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (kernel memory
exhaustion). (CVE-2019-19071)

It was discovered that the Broadcom Netxtreme HCA device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-19077)

It was discovered that the Atheros 802.11ac wireless USB device driver in
the Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-19078)

It was discovered that the Qualcomm IPC Router TUN device driver in the
Linux kernel did not properly deallocate memory in certain situations. A
local attacker could possibly use this to cause a denial of service (kernel
memory exhaustion). (CVE-2019-19079)

It was discovered that the AMD GPU device drivers in the Linux kernel did
not properly deallocate memory in certain error conditions. A local
attacker could use this to possibly cause a denial of service (kernel
memory exhaustion). (CVE-2019-19082)

Dan Carpenter discovered that the AppleTalk networking subsystem of the
Linux kernel did not properly handle certain error conditions, leading to a
NULL pointer dereference. A local attacker could use this to cause a denial
of service (system crash). (CVE-2019-19227)

Or Cohen discovered that the virtual console subsystem in the Linux kernel
did not properly restrict writes to unimplemented vcsu (unicode) devices. A
local attacker could possibly use this to cause a denial of service (system
crash) or have other unspecified impacts. (CVE-2019-19252)

It was discovered that the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-aws-5.0, linux-gcp, linux-gke-5.0, linux-meta-aws-5.0, linux-meta-gcp, linux-meta-gke-5.0, linux-meta-oracle-5.0, linux-oracle-5.0, linux-signed-gcp, linux-signed-gke-5.0, linux-signed-oracle-5.0' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
