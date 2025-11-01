# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845079");
  script_cve_id("CVE-2021-33624", "CVE-2021-34556", "CVE-2021-35477", "CVE-2021-3679", "CVE-2021-37159", "CVE-2021-37576", "CVE-2021-38160", "CVE-2021-38199", "CVE-2021-38201", "CVE-2021-38204", "CVE-2021-38205", "CVE-2021-41073");
  script_tag(name:"creation_date", value:"2021-09-30 01:00:25 +0000 (Thu, 30 Sep 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-02 03:15:00 +0000 (Sat, 02 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5092-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5092-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5092-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-5.11, linux-hwe-5.11, linux-meta-azure, linux-meta-azure-5.11, linux-meta-hwe-5.11, linux-meta-oracle-5.11, linux-oracle-5.11, linux-signed-azure, linux-signed-azure-5.11, linux-signed-hwe-5.11, linux-signed-oracle-5.11' package(s) announced via the USN-5092-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Valentina Palmiotti discovered that the io_uring subsystem in the Linux
kernel could be coerced to free adjacent memory. A local attacker could use
this to execute arbitrary code. (CVE-2021-41073)

Ofek Kirzner, Adam Morrison, Benedict Schlueter, and Piotr Krysiuk
discovered that the BPF verifier in the Linux kernel missed possible
mispredicted branches due to type confusion, allowing a side-channel
attack. An attacker could use this to expose sensitive information.
(CVE-2021-33624)

Benedict Schlueter discovered that the BPF subsystem in the Linux kernel
did not properly protect against Speculative Store Bypass (SSB) side-
channel attacks in some situations. A local attacker could possibly use
this to expose sensitive information. (CVE-2021-34556)

Piotr Krysiuk discovered that the BPF subsystem in the Linux kernel did not
properly protect against Speculative Store Bypass (SSB) side-channel
attacks in some situations. A local attacker could possibly use this to
expose sensitive information. (CVE-2021-35477)

It was discovered that the tracing subsystem in the Linux kernel did not
properly keep track of per-cpu ring buffer state. A privileged attacker
could use this to cause a denial of service. (CVE-2021-3679)

It was discovered that the Option USB High Speed Mobile device driver in
the Linux kernel did not properly handle error conditions. A physically
proximate attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2021-37159)

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

It was discovered that the Sun RPC implementation in the Linux kernel
contained an out-of-bounds access error. A remote attacker could possibly
use this to cause a denial of service (system crash). (CVE-2021-38201)

It was discovered that the MAX-3421 host USB device driver in the Linux
kernel did not properly handle device removal events. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2021-38204)

It was discovered that the Xilinx 10/100 Ethernet Lite device driver in the
Linux kernel could report pointer addresses in some situations. An attacker
could ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-5.11, linux-hwe-5.11, linux-meta-azure, linux-meta-azure-5.11, linux-meta-hwe-5.11, linux-meta-oracle-5.11, linux-oracle-5.11, linux-signed-azure, linux-signed-azure-5.11, linux-signed-hwe-5.11, linux-signed-oracle-5.11' package(s) on Ubuntu 20.04, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
