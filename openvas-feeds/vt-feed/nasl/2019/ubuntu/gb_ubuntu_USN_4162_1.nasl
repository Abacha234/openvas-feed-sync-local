# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844208");
  script_cve_id("CVE-2018-21008", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15505", "CVE-2019-15902", "CVE-2019-15918");
  script_tag(name:"creation_date", value:"2019-10-23 02:01:08 +0000 (Wed, 23 Oct 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-04 05:15:00 +0000 (Wed, 04 Sep 2019)");

  script_name("Ubuntu: Security Advisory (USN-4162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4162-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4162-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the RSI 91x Wi-Fi driver in the Linux kernel did not
did not handle detach operations correctly, leading to a use-after-free
vulnerability. A physically proximate attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2018-21008)

Wen Huang discovered that the Marvell Wi-Fi device driver in the Linux
kernel did not properly perform bounds checking, leading to a heap
overflow. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-14814,
CVE-2019-14815, CVE-2019-14816)

Matt Delco discovered that the KVM hypervisor implementation in the Linux
kernel did not properly perform bounds checking when handling coalesced
MMIO write operations. A local attacker with write access to /dev/kvm could
use this to cause a denial of service (system crash). (CVE-2019-14821)

Hui Peng and Mathias Payer discovered that the USB audio driver for the
Linux kernel did not properly validate device meta data. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2019-15117)

Hui Peng and Mathias Payer discovered that the USB audio driver for the
Linux kernel improperly performed recursion while handling device meta
data. A physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2019-15118)

It was discovered that the Technisat DVB-S/S2 USB device driver in the
Linux kernel contained a buffer overread. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
expose sensitive information. (CVE-2019-15505)

Brad Spengler discovered that a Spectre mitigation was improperly
implemented in the ptrace subsystem of the Linux kernel. A local attacker
could possibly use this to expose sensitive information. (CVE-2019-15902)

It was discovered that the SMB networking file system implementation in the
Linux kernel contained a buffer overread. An attacker could use this to
expose sensitive information (kernel memory). (CVE-2019-15918)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
