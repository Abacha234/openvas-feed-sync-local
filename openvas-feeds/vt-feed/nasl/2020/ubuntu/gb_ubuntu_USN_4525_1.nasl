# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844605");
  script_cve_id("CVE-2019-18808", "CVE-2019-19054", "CVE-2020-12888", "CVE-2020-16166", "CVE-2020-25212");
  script_tag(name:"creation_date", value:"2020-09-23 03:00:34 +0000 (Wed, 23 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-4525-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4525-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4525-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-hwe-5.4, linux-meta, linux-meta-azure, linux-meta-gcp, linux-meta-oracle, linux-oracle, linux-oracle-5.4, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-oracle' package(s) announced via the USN-4525-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the AMD Cryptographic Coprocessor device driver in
the Linux kernel did not properly deallocate memory in some situations. A
local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-18808)

It was discovered that the Conexant 23885 TV card device driver for the
Linux kernel did not properly deallocate memory in some error conditions. A
local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-19054)

It was discovered that the VFIO PCI driver in the Linux kernel did not
properly handle attempts to access disabled memory spaces. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2020-12888)

It was discovered that the state of network RNG in the Linux kernel was
potentially observable. A remote attacker could use this to expose
sensitive information. (CVE-2020-16166)

It was discovered that the NFS client implementation in the Linux kernel
did not properly perform bounds checking before copying security labels in
some situations. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2020-25212)");

  script_tag(name:"affected", value:"'linux, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-hwe-5.4, linux-meta, linux-meta-azure, linux-meta-gcp, linux-meta-oracle, linux-oracle, linux-oracle-5.4, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-oracle' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
