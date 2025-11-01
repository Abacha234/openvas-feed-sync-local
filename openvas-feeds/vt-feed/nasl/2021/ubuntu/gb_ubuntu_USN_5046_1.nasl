# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845030");
  script_cve_id("CVE-2020-26558", "CVE-2021-0129", "CVE-2021-28691", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-3587");
  script_tag(name:"creation_date", value:"2021-08-18 07:49:36 +0000 (Wed, 18 Aug 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-24 19:21:00 +0000 (Tue, 24 Aug 2021)");

  script_name("Ubuntu: Security Advisory (USN-5046-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5046-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5046-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.11, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-hwe-5.11, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-hwe-5.11, linux-signed-kvm, linux-signed-oracle' package(s) announced via the USN-5046-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the bluetooth subsystem in the Linux kernel did not
properly perform access control. An authenticated attacker could possibly
use this to expose sensitive information. (CVE-2020-26558, CVE-2021-0129)

Michael Brown discovered that the Xen netback driver in the Linux kernel
did not properly handle malformed packets from a network PV frontend,
leading to a use-after-free vulnerability. An attacker in a guest VM could
use this to cause a denial of service or possibly execute arbitrary code.
(CVE-2021-28691)

It was discovered that the bluetooth subsystem in the Linux kernel did not
properly handle HCI device initialization failure, leading to a double-free
vulnerability. An attacker could use this to cause a denial of service or
possibly execute arbitrary code. (CVE-2021-3564)

It was discovered that the bluetooth subsystem in the Linux kernel did not
properly handle HCI device detach events, leading to a use-after-free
vulnerability. An attacker could use this to cause a denial of service or
possibly execute arbitrary code. (CVE-2021-3573)

It was discovered that the NFC implementation in the Linux kernel did not
properly handle failed connect events leading to a NULL pointer
dereference. A local attacker could use this to cause a denial of service.
(CVE-2021-3587)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.11, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-hwe-5.11, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-hwe-5.11, linux-signed-kvm, linux-signed-oracle' package(s) on Ubuntu 20.04, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
