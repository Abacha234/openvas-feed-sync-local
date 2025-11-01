# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845220");
  script_cve_id("CVE-2021-3489", "CVE-2021-3490", "CVE-2021-3491");
  script_tag(name:"creation_date", value:"2022-01-28 08:01:37 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4950-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4950-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4950-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1927409");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-kvm, linux-signed-oracle' package(s) announced via the USN-4950-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ryota Shiga discovered that the eBPF implementation in the Linux kernel did
not properly verify that a BPF program only reserved as much memory for a
ring buffer as was allocated. A local attacker could use this to cause a
denial of service (system crash) or execute arbitrary code. (CVE-2021-3489)

Manfred Paul discovered that the eBPF implementation in the Linux kernel
did not properly track bounds on bitwise operations. A local attacker could
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2021-3490)

Billy Jheng Bing-Jhong discovered that the io_uring implementation of the
Linux kernel did not properly enforce the MAX_RW_COUNT limit in some
situations. A local attacker could use this to cause a denial of service
(system crash) or execute arbitrary code. (CVE-2021-3491)

Norbert Slusarek discovered that the CAN ISOTP protocol implementation
in the Linux kernel contained a race condition. A local attacker could
use this to cause a denial of service (system crash) or possibly
execute arbitrary code. Please note that to address this issue,
SF_BROADCAST support was removed temporarily from the CAN ISOTP
implementation in Ubuntu 21.04 kernels. (LP: #1927409)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-kvm, linux-signed-oracle' package(s) on Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
