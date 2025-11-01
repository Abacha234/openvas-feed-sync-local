# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845368");
  script_cve_id("CVE-2020-27820", "CVE-2021-26401", "CVE-2022-1016", "CVE-2022-20008", "CVE-2022-25258", "CVE-2022-25375", "CVE-2022-26490", "CVE-2022-27223");
  script_tag(name:"creation_date", value:"2022-05-13 01:00:48 +0000 (Fri, 13 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 16:12:00 +0000 (Tue, 22 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5415-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5415-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5415-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-azure-5.4, linux-azure-fde, linux-gcp, linux-gcp-5.4, linux-gke, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-ibm, linux-ibm-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-azure-5.4, linux-meta-azure-fde, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-ibm, linux-meta-ibm-5.4, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-aws, linux-signed-azure, linux-signed-azure-5.4, linux-signed-azure-fde, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-ibm, linux-signed-ibm-5.4, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.4' package(s) announced via the USN-5415-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeremy Cline discovered a use-after-free in the nouveau graphics driver of
the Linux kernel during device removal. A privileged or physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2020-27820)

Ke Sun, Alyssa Milburn, Henrique Kawakami, Emma Benoit, Igor Chervatyuk,
Lisa Aichele, and Thais Moreira Hamasaki discovered that the Spectre
Variant 2 mitigations for AMD processors on Linux were insufficient in some
situations. A local attacker could possibly use this to expose sensitive
information. (CVE-2021-26401)

David Bouman discovered that the netfilter subsystem in the Linux kernel
did not initialize memory in some situations. A local attacker could use
this to expose sensitive information (kernel memory). (CVE-2022-1016)

It was discovered that the MMC/SD subsystem in the Linux kernel did not
properly handle read errors from SD cards in certain situations. An
attacker could possibly use this to expose sensitive information (kernel
memory). (CVE-2022-20008)

It was discovered that the USB gadget subsystem in the Linux kernel did not
properly validate interface descriptor requests. An attacker could possibly
use this to cause a denial of service (system crash). (CVE-2022-25258)

It was discovered that the Remote NDIS (RNDIS) USB gadget implementation in
the Linux kernel did not properly validate the size of the RNDIS_MSG_SET
command. An attacker could possibly use this to expose sensitive
information (kernel memory). (CVE-2022-25375)

It was discovered that the ST21NFCA NFC driver in the Linux kernel did not
properly validate the size of certain data in EVT_TRANSACTION events. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-26490)

It was discovered that the Xilinx USB2 device gadget driver in the Linux
kernel did not properly validate endpoint indices from the host. A
physically proximate attacker could possibly use this to cause a denial of
service (system crash). (CVE-2022-27223)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-azure-5.4, linux-azure-fde, linux-gcp, linux-gcp-5.4, linux-gke, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-ibm, linux-ibm-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-azure-5.4, linux-meta-azure-fde, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-ibm, linux-meta-ibm-5.4, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-aws, linux-signed-azure, linux-signed-azure-5.4, linux-signed-azure-fde, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-ibm, linux-signed-ibm-5.4, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
