# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844969");
  script_cve_id("CVE-2021-29155", "CVE-2021-31829", "CVE-2021-33200", "CVE-2021-3501");
  script_tag(name:"creation_date", value:"2021-06-04 03:00:41 +0000 (Fri, 04 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-06 08:15:00 +0000 (Tue, 06 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4983-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4983-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4983-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta-oem-5.10, linux-oem-5.10, linux-signed-oem-5.10' package(s) announced via the USN-4983-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Piotr Krysiuk discovered that the eBPF implementation in the Linux kernel
did not properly enforce limits for pointer operations. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2021-33200)

Piotr Krysiuk and Benedict Schlueter discovered that the eBPF
implementation in the Linux kernel performed out of bounds speculation on
pointer arithmetic. A local attacker could use this to expose sensitive
information. (CVE-2021-29155)

Piotr Krysiuk discovered that the eBPF implementation in the Linux kernel
did not properly prevent speculative loads in certain situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2021-31829)

Reiji Watanabe discovered that the KVM VMX implementation in the Linux
kernel did not properly prevent user space from tampering with an array
index value, leading to a potential out-of-bounds write. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2021-3501)");

  script_tag(name:"affected", value:"'linux-meta-oem-5.10, linux-oem-5.10, linux-signed-oem-5.10' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
