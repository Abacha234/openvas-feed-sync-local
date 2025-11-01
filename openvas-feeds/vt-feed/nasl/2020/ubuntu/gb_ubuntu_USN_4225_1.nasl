# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844284");
  script_cve_id("CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-14901", "CVE-2019-16231", "CVE-2019-18660", "CVE-2019-18813", "CVE-2019-19044", "CVE-2019-19045", "CVE-2019-19047", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19055", "CVE-2019-19072", "CVE-2019-19524", "CVE-2019-19529", "CVE-2019-19534", "CVE-2019-19807");
  script_tag(name:"creation_date", value:"2020-01-08 11:16:46 +0000 (Wed, 08 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-12 16:15:00 +0000 (Thu, 12 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-4225-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4225-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4225-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-azure-5.3, linux-gcp, linux-gcp-5.3, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-azure-5.3, linux-meta-gcp, linux-meta-gcp-5.3, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-azure-5.3, linux-signed-gcp, linux-signed-gcp-5.3, linux-signed-oracle' package(s) announced via the USN-4225-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a heap-based buffer overflow existed in the Marvell
WiFi-Ex Driver for the Linux kernel. A physically proximate attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-14895, CVE-2019-14901)

It was discovered that a heap-based buffer overflow existed in the Marvell
Libertas WLAN Driver for the Linux kernel. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2019-14896, CVE-2019-14897)

It was discovered that the Fujitsu ES network device driver for the Linux
kernel did not properly check for errors in some situations, leading to a
NULL pointer dereference. A local attacker could use this to cause a denial
of service. (CVE-2019-16231)

Anthony Steinhauser discovered that the Linux kernel did not properly
perform Spectre_RSB mitigations to all processors for PowerPC architecture
systems in some situations. A local attacker could use this to expose
sensitive information. (CVE-2019-18660)

It was discovered that the Broadcom V3D DRI driver in the Linux kernel did
not properly deallocate memory in certain error conditions. A local
attacker could possibly use this to cause a denial of service (kernel
memory exhaustion). (CVE-2019-19044)

It was discovered that the Mellanox Technologies Innova driver in the Linux
kernel did not properly deallocate memory in certain failure conditions. A
local attacker could use this to cause a denial of service (kernel memory
exhaustion). (CVE-2019-19045)

It was discovered that the Mellanox Technologies ConnectX driver in the
Linux kernel did not properly deallocate memory in certain failure
conditions. A local attacker could use this to cause a denial of service
(kernel memory exhaustion). (CVE-2019-19047)

It was discovered that the Intel WiMAX 2400 driver in the Linux kernel did
not properly deallocate memory in certain situations. A local attacker
could use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19051)

It was discovered that Geschwister Schneider USB CAN interface driver in
the Linux kernel did not properly deallocate memory in certain failure
conditions. A physically proximate attacker could use this to cause a
denial of service (kernel memory exhaustion). (CVE-2019-19052)

It was discovered that the netlink-based 802.11 configuration interface in
the Linux kernel did not deallocate memory in certain error conditions. A
local attacker could possibly use this to cause a denial of service (kernel
memory exhaustion). (CVE-2019-19055)

It was discovered that the event tracing subsystem of the Linux kernel did
not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (kernel memory
exhaustion). (CVE-2019-19072)

It was discovered that the driver for memoryless force-feedback input
devices ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-azure-5.3, linux-gcp, linux-gcp-5.3, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-azure-5.3, linux-meta-gcp, linux-meta-gcp-5.3, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-azure-5.3, linux-signed-gcp, linux-signed-gcp-5.3, linux-signed-oracle' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
