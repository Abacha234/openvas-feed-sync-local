# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844828");
  script_cve_id("CVE-2021-26708");
  script_tag(name:"creation_date", value:"2021-02-11 04:00:20 +0000 (Thu, 11 Feb 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-09 12:15:00 +0000 (Fri, 09 Apr 2021)");

  script_name("Ubuntu: Security Advisory (USN-4727-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4727-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4727-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oem-5.6, linux-meta-oracle, linux-meta-raspi, linux-oem-5.6, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oem-5.6, linux-signed-oracle' package(s) announced via the USN-4727-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander Popov discovered that multiple race conditions existed in the
AF_VSOCK implementation in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or execute arbitrary code.");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oem-5.6, linux-meta-oracle, linux-meta-raspi, linux-oem-5.6, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oem-5.6, linux-signed-oracle' package(s) on Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
