# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844483");
  script_cve_id("CVE-2020-10711", "CVE-2020-10732", "CVE-2020-12768", "CVE-2020-12770", "CVE-2020-13143");
  script_tag(name:"creation_date", value:"2020-07-03 03:01:33 +0000 (Fri, 03 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-29 19:15:00 +0000 (Wed, 29 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-4411-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4411-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4411-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gcp, linux-meta-kvm, linux-meta-oracle, linux-meta-riscv, linux-oracle, linux-riscv, linux-signed, linux-signed-gcp, linux-signed-oracle' package(s) announced via the USN-4411-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the elf handling code in the Linux kernel did not
initialize memory before using it in certain situations. A local attacker
could use this to possibly expose sensitive information (kernel memory).
(CVE-2020-10732)

Matthew Sheets discovered that the SELinux network label handling
implementation in the Linux kernel could be coerced into de-referencing a
NULL pointer. A remote attacker could use this to cause a denial of service
(system crash). (CVE-2020-10711)

It was discovered that the SCSI generic (sg) driver in the Linux kernel did
not properly handle certain error conditions correctly. A local privileged
attacker could use this to cause a denial of service (system crash).
(CVE-2020-12770)

It was discovered that the USB Gadget device driver in the Linux kernel did
not validate arguments passed from configfs in some situations. A local
attacker could possibly use this to cause a denial of service (system
crash) or possibly expose sensitive information. (CVE-2020-13143)

It was discovered that the KVM implementation in the Linux kernel did not
properly deallocate memory on initialization for some processors. A local
attacker could possibly use this to cause a denial of service.
(CVE-2020-12768)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gcp, linux-meta-kvm, linux-meta-oracle, linux-meta-riscv, linux-oracle, linux-riscv, linux-signed, linux-signed-gcp, linux-signed-oracle' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
