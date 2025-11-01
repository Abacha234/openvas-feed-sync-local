# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845438");
  script_cve_id("CVE-2021-4197", "CVE-2022-1011", "CVE-2022-1198", "CVE-2022-1199", "CVE-2022-1204", "CVE-2022-1205", "CVE-2022-1353", "CVE-2022-1516", "CVE-2022-2380", "CVE-2022-28389");
  script_tag(name:"creation_date", value:"2022-07-14 01:00:29 +0000 (Thu, 14 Jul 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-09 15:32:00 +0000 (Sat, 09 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5515-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5515-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5515-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-aws, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-5515-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eric Biederman discovered that the cgroup process migration implementation
in the Linux kernel did not perform permission checks correctly in some
situations. A local attacker could possibly use this to gain administrative
privileges. (CVE-2021-4197)

Jann Horn discovered that the FUSE file system in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-1011)

Duoming Zhou discovered that the 6pack protocol implementation in the Linux
kernel did not handle detach events properly in some situations, leading to
a use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash). (CVE-2022-1198)

Duoming Zhou discovered that the AX.25 amateur radio protocol
implementation in the Linux kernel did not handle detach events properly in
some situations. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2022-1199)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel during device detach operations. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-1204)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel, leading to use-after-free
vulnerabilities. A local attacker could possibly use this to cause a denial
of service (system crash). (CVE-2022-1205)

It was discovered that the PF_KEYv2 implementation in the Linux kernel did
not properly initialize kernel memory in some situations. A local attacker
could use this to expose sensitive information (kernel memory).
(CVE-2022-1353)

It was discovered that the implementation of X.25 network protocols in the
Linux kernel did not terminate link layer sessions properly. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-1516)

Zheyu Ma discovered that the Silicon Motion SM712 framebuffer driver in the
Linux kernel did not properly handle very small reads. A local attacker
could use this to cause a denial of service (system crash). (CVE-2022-2380)

It was discovered that the Microchip CAN BUS Analyzer interface
implementation in the Linux kernel did not properly handle certain error
conditions, leading to a double-free. A local attacker could possibly use
this to cause a denial of service (system crash). (CVE-2022-28389)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-aws, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
