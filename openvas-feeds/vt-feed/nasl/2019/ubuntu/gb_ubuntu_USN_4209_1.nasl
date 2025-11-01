# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844259");
  script_cve_id("CVE-2019-15794", "CVE-2019-16746", "CVE-2019-19076");
  script_tag(name:"creation_date", value:"2019-12-04 03:02:03 +0000 (Wed, 04 Dec 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4209-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4209-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4209-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.0, linux-gcp, linux-gke-5.0, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.0, linux-meta-gcp, linux-meta-gke-5.0, linux-meta-hwe, linux-meta-kvm, linux-meta-oem-osp1, linux-meta-oracle, linux-meta-oracle-5.0, linux-meta-raspi2, linux-oem-osp1, linux-oracle, linux-oracle-5.0, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-gke-5.0, linux-signed-hwe, linux-signed-oem-osp1, linux-signed-oracle, linux-signed-oracle-5.0' package(s) announced via the USN-4209-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the OverlayFS and ShiftFS Drivers in the Linux
kernel did not properly handle reference counting during memory mapping
operations when used in conjunction with AUFS. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-15794)

It was discovered that a buffer overflow existed in the 802.11 Wi-Fi
configuration interface for the Linux kernel when handling beacon settings.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2019-16746)

It was discovered that there was a memory leak in the Advanced Buffer
Management functionality of the Netronome NFP4000/NFP6000 NIC Driver in the
Linux kernel during certain error scenarios. A local attacker could use
this to cause a denial of service (memory exhaustion). (CVE-2019-19076)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.0, linux-gcp, linux-gke-5.0, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.0, linux-meta-gcp, linux-meta-gke-5.0, linux-meta-hwe, linux-meta-kvm, linux-meta-oem-osp1, linux-meta-oracle, linux-meta-oracle-5.0, linux-meta-raspi2, linux-oem-osp1, linux-oracle, linux-oracle-5.0, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-gke-5.0, linux-signed-hwe, linux-signed-oem-osp1, linux-signed-oracle, linux-signed-oracle-5.0' package(s) on Ubuntu 18.04, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
