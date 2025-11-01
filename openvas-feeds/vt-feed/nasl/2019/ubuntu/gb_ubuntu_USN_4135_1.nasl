# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844182");
  script_cve_id("CVE-2019-14835", "CVE-2019-15030", "CVE-2019-15031");
  script_tag(name:"creation_date", value:"2019-09-19 02:03:10 +0000 (Thu, 19 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 15:44:00 +0000 (Wed, 02 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4135-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4135-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4135-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gke-4.15, linux-gke-5.0, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-gke-5.0, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-gke-5.0, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4135-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Peter Pi discovered a buffer overflow in the virtio network backend
(vhost_net) implementation in the Linux kernel. An attacker in a guest may
be able to use this to cause a denial of service (host OS crash) or
possibly execute arbitrary code in the host OS. (CVE-2019-14835)

It was discovered that the Linux kernel on PowerPC architectures did not
properly handle Facility Unavailable exceptions in some situations. A local
attacker could use this to expose sensitive information. (CVE-2019-15030)

It was discovered that the Linux kernel on PowerPC architectures did not
properly handle exceptions on interrupts in some situations. A local
attacker could use this to expose sensitive information. (CVE-2019-15031)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gke-4.15, linux-gke-5.0, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-gke-5.0, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-gke-5.0, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
