# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844347");
  script_cve_id("CVE-2019-14615", "CVE-2019-15099", "CVE-2019-15291", "CVE-2019-16229", "CVE-2019-16232", "CVE-2019-18683", "CVE-2019-18786", "CVE-2019-18809", "CVE-2019-18885", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19071", "CVE-2019-19078", "CVE-2019-19082", "CVE-2019-19227", "CVE-2019-19332", "CVE-2019-19767", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-5108", "CVE-2020-7053");
  script_tag(name:"creation_date", value:"2020-02-19 04:01:16 +0000 (Wed, 19 Feb 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4287-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4287-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4287-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4287-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not properly clear data
structures on context switches for certain Intel graphics processors. A
local attacker could use this to expose sensitive information.
(CVE-2019-14615)

It was discovered that the Atheros 802.11ac wireless USB device driver in
the Linux kernel did not properly validate device metadata. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2019-15099)

It was discovered that the HSA Linux kernel driver for AMD GPU devices did
not properly check for errors in certain situations, leading to a NULL
pointer dereference. A local attacker could possibly use this to cause a
denial of service. (CVE-2019-16229)

It was discovered that the Marvell 8xxx Libertas WLAN device driver in the
Linux kernel did not properly check for errors in certain situations,
leading to a NULL pointer dereference. A local attacker could possibly use
this to cause a denial of service. (CVE-2019-16232)

It was discovered that a race condition existed in the Virtual Video Test
Driver in the Linux kernel. An attacker with write access to /dev/video0 on
a system with the vivid module loaded could possibly use this to gain
administrative privileges. (CVE-2019-18683)

It was discovered that the Renesas Digital Radio Interface (DRIF) driver in
the Linux kernel did not properly initialize data. A local attacker could
possibly use this to expose sensitive information (kernel memory).
(CVE-2019-18786)

It was discovered that the Afatech AF9005 DVB-T USB device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-18809)

It was discovered that the btrfs file system in the Linux kernel did not
properly validate metadata, leading to a NULL pointer dereference. An
attacker could use this to specially craft a file system image that, when
mounted, could cause a denial of service (system crash). (CVE-2019-18885)

It was discovered that multiple memory leaks existed in the Marvell WiFi-Ex
Driver for the Linux kernel. A local attacker could possibly use this to
cause a denial of service (kernel memory exhaustion). (CVE-2019-19057)

It was discovered that the crypto subsystem in the Linux kernel did not
properly deallocate memory in certain error conditions. A local attacker
could use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19062)

It was discovered that the Realtek rtlwifi USB device driver in the Linux
kernel did not properly deallocate memory in certain error conditions. A
local attacker could possibly use this to cause a denial of service (kernel
memory exhaustion). (CVE-2019-19063)

It was discovered that the RSI 91x WLAN device driver in the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
