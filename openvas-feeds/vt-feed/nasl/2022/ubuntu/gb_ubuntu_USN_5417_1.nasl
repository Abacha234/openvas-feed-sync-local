# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845366");
  script_cve_id("CVE-2021-26401", "CVE-2022-20008", "CVE-2022-25258", "CVE-2022-25375", "CVE-2022-26490", "CVE-2022-26966", "CVE-2022-27223", "CVE-2022-29156");
  script_tag(name:"creation_date", value:"2022-05-13 01:00:38 +0000 (Fri, 13 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-20 16:26:00 +0000 (Wed, 20 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5417-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5417-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5417-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.13, linux-azure, linux-azure-5.13, linux-gcp, linux-gcp-5.13, linux-hwe-5.13, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.13, linux-meta-azure, linux-meta-azure-5.13, linux-meta-gcp, linux-meta-gcp-5.13, linux-meta-hwe-5.13, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-aws, linux-signed-aws-5.13, linux-signed-azure, linux-signed-azure-5.13, linux-signed-gcp, linux-signed-gcp-5.13, linux-signed-hwe-5.13, linux-signed-kvm, linux-signed-oracle' package(s) announced via the USN-5417-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ke Sun, Alyssa Milburn, Henrique Kawakami, Emma Benoit, Igor Chervatyuk,
Lisa Aichele, and Thais Moreira Hamasaki discovered that the Spectre
Variant 2 mitigations for AMD processors on Linux were insufficient in some
situations. A local attacker could possibly use this to expose sensitive
information. (CVE-2021-26401)

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

It was discovered that the USB SR9700 ethernet device driver for the Linux
kernel did not properly validate the length of requests from the device. A
physically proximate attacker could possibly use this to expose sensitive
information (kernel memory). (CVE-2022-26966)

It was discovered that the Xilinx USB2 device gadget driver in the Linux
kernel did not properly validate endpoint indices from the host. A
physically proximate attacker could possibly use this to cause a denial of
service (system crash). (CVE-2022-27223)

Miaoqian Lin discovered that the RDMA Transport (RTRS) client
implementation in the Linux kernel contained a double-free when handling
certain error conditions. An attacker could use this to cause a denial of
service (system crash). (CVE-2022-29156)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.13, linux-azure, linux-azure-5.13, linux-gcp, linux-gcp-5.13, linux-hwe-5.13, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.13, linux-meta-azure, linux-meta-azure-5.13, linux-meta-gcp, linux-meta-gcp-5.13, linux-meta-hwe-5.13, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-aws, linux-signed-aws-5.13, linux-signed-azure, linux-signed-azure-5.13, linux-signed-gcp, linux-signed-gcp-5.13, linux-signed-hwe-5.13, linux-signed-kvm, linux-signed-oracle' package(s) on Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
