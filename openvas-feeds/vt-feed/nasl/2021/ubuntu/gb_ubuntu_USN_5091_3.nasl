# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845099");
  script_cve_id("CVE-2021-33624", "CVE-2021-3679", "CVE-2021-37576", "CVE-2021-38160", "CVE-2021-38199", "CVE-2021-38204");
  script_tag(name:"creation_date", value:"2021-10-16 01:02:01 +0000 (Sat, 16 Oct 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5091-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5091-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5091-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1940564");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-signed-azure, linux-signed-azure-5.4' package(s) announced via the USN-5091-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5091-1 fixed vulnerabilities in Linux 5.4-based kernels.
Unfortunately, for Linux kernels intended for use within Microsoft
Azure environments, that update introduced a regression that could
cause the kernel to fail to boot in large Azure instance types.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Ofek Kirzner, Adam Morrison, Benedict Schlueter, and Piotr Krysiuk
 discovered that the BPF verifier in the Linux kernel missed possible
 mispredicted branches due to type confusion, allowing a side-channel
 attack. An attacker could use this to expose sensitive information.
 (CVE-2021-33624)

 It was discovered that the tracing subsystem in the Linux kernel did not
 properly keep track of per-cpu ring buffer state. A privileged attacker
 could use this to cause a denial of service. (CVE-2021-3679)

 Alexey Kardashevskiy discovered that the KVM implementation for PowerPC
 systems in the Linux kernel did not properly validate RTAS arguments in
 some situations. An attacker in a guest vm could use this to cause a denial
 of service (host OS crash) or possibly execute arbitrary code.
 (CVE-2021-37576)

 It was discovered that the Virtio console implementation in the Linux
 kernel did not properly validate input lengths in some situations. A local
 attacker could possibly use this to cause a denial of service (system
 crash). (CVE-2021-38160)

 Michael Wakabayashi discovered that the NFSv4 client implementation in the
 Linux kernel did not properly order connection setup operations. An
 attacker controlling a remote NFS server could use this to cause a denial
 of service on the client. (CVE-2021-38199)

 It was discovered that the MAX-3421 host USB device driver in the Linux
 kernel did not properly handle device removal events. A physically
 proximate attacker could use this to cause a denial of service (system
 crash). (CVE-2021-38204)");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-signed-azure, linux-signed-azure-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
