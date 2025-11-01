# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843418");
  script_cve_id("CVE-2017-16995", "CVE-2017-17862", "CVE-2017-17863", "CVE-2017-17864", "CVE-2017-5754");
  script_tag(name:"creation_date", value:"2018-01-11 06:38:59 +0000 (Thu, 11 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)");

  script_name("Ubuntu: Security Advisory (USN-3523-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3523-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3523-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-gcp, linux-hwe, linux-meta-azure, linux-meta-gcp, linux-meta-hwe, linux-meta-oem, linux-oem' package(s) announced via the USN-3523-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3523-1 fixed vulnerabilities in the Linux kernel for Ubuntu 17.10.
This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 17.10 for Ubuntu
16.04 LTS.

Jann Horn discovered that microprocessors utilizing speculative execution
and indirect branch prediction may allow unauthorized memory reads via
sidechannel attacks. This flaw is known as Meltdown. A local attacker could
use this to expose sensitive information, including kernel memory.
(CVE-2017-5754)

Jann Horn discovered that the Berkeley Packet Filter (BPF) implementation
in the Linux kernel did not properly check the relationship between pointer
values and the BPF stack. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2017-17863)

Jann Horn discovered that the Berkeley Packet Filter (BPF) implementation
in the Linux kernel improperly performed sign extension in some situations.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2017-16995)

Alexei Starovoitov discovered that the Berkeley Packet Filter (BPF)
implementation in the Linux kernel contained a branch-pruning logic issue
around unreachable code. A local attacker could use this to cause a denial
of service. (CVE-2017-17862)

Jann Horn discovered that the Berkeley Packet Filter (BPF) implementation
in the Linux kernel mishandled pointer data values in some situations. A
local attacker could use this to expose sensitive information (kernel
memory). (CVE-2017-17864)");

  script_tag(name:"affected", value:"'linux-azure, linux-gcp, linux-hwe, linux-meta-azure, linux-meta-gcp, linux-meta-hwe, linux-meta-oem, linux-oem' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
