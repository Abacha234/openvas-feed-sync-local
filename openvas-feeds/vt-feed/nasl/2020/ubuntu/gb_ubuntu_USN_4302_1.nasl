# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844364");
  script_cve_id("CVE-2019-14615", "CVE-2019-15217", "CVE-2019-19046", "CVE-2019-19051", "CVE-2019-19056", "CVE-2019-19058", "CVE-2019-19066", "CVE-2019-19068", "CVE-2020-2732", "CVE-2020-8832");
  script_tag(name:"creation_date", value:"2020-03-17 04:00:29 +0000 (Tue, 17 Mar 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4302-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4302-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4302-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-snapdragon' package(s) announced via the USN-4302-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paulo Bonzini discovered that the KVM hypervisor implementation in the
Linux kernel could improperly let a nested (level 2) guest access the
resources of a parent (level 1) guest in certain situations. An attacker
could use this to expose sensitive information. (CVE-2020-2732)

Gregory Herrero discovered that the fix for CVE-2019-14615 to address the
Linux kernel not properly clearing data structures on context switches for
certain Intel graphics processors was incomplete. A local attacker could
use this to expose sensitive information. (CVE-2020-8832)

It was discovered that the IPMI message handler implementation in the Linux
kernel did not properly deallocate memory in certain situations. A local
attacker could use this to cause a denial of service (kernel memory
exhaustion). (CVE-2019-19046)

It was discovered that the Intel WiMAX 2400 driver in the Linux kernel did
not properly deallocate memory in certain situations. A local attacker
could use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19051)

It was discovered that the Marvell Wi-Fi device driver in the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to possibly cause a denial of service (kernel
memory exhaustion). (CVE-2019-19056)

It was discovered that the Intel(R) Wi-Fi device driver in the Linux kernel
device driver in the Linux kernel did not properly deallocate memory in
certain error conditions. A local attacker could possibly use this to cause
a denial of service (kernel memory exhaustion). (CVE-2019-19058)

It was discovered that the Brocade BFA Fibre Channel device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-19066)

It was discovered that the Realtek RTL8xxx USB Wi-Fi device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-19068)

It was discovered that ZR364XX Camera USB device driver for the Linux
kernel did not properly initialize memory. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2019-15217)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
