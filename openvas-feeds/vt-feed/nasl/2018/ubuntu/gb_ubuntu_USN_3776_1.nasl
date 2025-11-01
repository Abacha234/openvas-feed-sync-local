# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843646");
  script_cve_id("CVE-2017-18216", "CVE-2018-10902", "CVE-2018-14633", "CVE-2018-15572", "CVE-2018-15594", "CVE-2018-16276", "CVE-2018-17182", "CVE-2018-6554", "CVE-2018-6555");
  script_tag(name:"creation_date", value:"2018-10-02 06:10:28 +0000 (Tue, 02 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-3776-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3776-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3776-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) announced via the USN-3776-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the vmacache subsystem did not properly handle
sequence number overflows, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or execute arbitrary code. (CVE-2018-17182)

It was discovered that the paravirtualization implementation in the Linux
kernel did not properly handle some indirect calls, reducing the
effectiveness of Spectre v2 mitigations for paravirtual guests. A local
attacker could use this to expose sensitive information. (CVE-2018-15594)

It was discovered that microprocessors utilizing speculative execution and
prediction of return addresses via Return Stack Buffer (RSB) may allow
unauthorized memory reads via sidechannel attacks. An attacker could use
this to expose sensitive information. (CVE-2018-15572)

It was discovered that a NULL pointer dereference could be triggered in the
OCFS2 file system implementation in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2017-18216)

It was discovered that a race condition existed in the raw MIDI driver for
the Linux kernel, leading to a double free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2018-10902)

It was discovered that a stack-based buffer overflow existed in the iSCSI
target implementation of the Linux kernel. A remote attacker could use this
to cause a denial of service (system crash). (CVE-2018-14633)

It was discovered that the YUREX USB device driver for the Linux kernel did
not properly restrict user space reads or writes. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-16276)

It was discovered that a memory leak existed in the IRDA subsystem of the
Linux kernel. A local attacker could use this to cause a denial of service
(kernel memory exhaustion). (CVE-2018-6554)

It was discovered that a use-after-free vulnerability existed in the IRDA
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-6555)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
