# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843139");
  script_cve_id("CVE-2017-5669", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-5986", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6347", "CVE-2017-6348", "CVE-2017-7374");
  script_tag(name:"creation_date", value:"2017-04-25 04:32:55 +0000 (Tue, 25 Apr 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-24 10:29:00 +0000 (Fri, 24 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-3265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3265-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3265-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gke, linux-meta, linux-meta-aws, linux-meta-gke, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) announced via the USN-3265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a use-after-free flaw existed in the filesystem
encryption subsystem in the Linux kernel. A local attacker could use this
to cause a denial of service (system crash). (CVE-2017-7374)

Andrey Konovalov discovered an out-of-bounds access in the IPv6 Generic
Routing Encapsulation (GRE) tunneling implementation in the Linux kernel.
An attacker could use this to possibly expose sensitive information.
(CVE-2017-5897)

Andrey Konovalov discovered that the IPv4 implementation in the Linux
kernel did not properly handle invalid IP options in some situations. An
attacker could use this to cause a denial of service or possibly execute
arbitrary code. (CVE-2017-5970)

Gareth Evans discovered that the shm IPC subsystem in the Linux kernel did
not properly restrict mapping page zero. A local privileged attacker could
use this to execute arbitrary code. (CVE-2017-5669)

Alexander Popov discovered that a race condition existed in the Stream
Control Transmission Protocol (SCTP) implementation in the Linux kernel. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2017-5986)

Dmitry Vyukov discovered that the Linux kernel did not properly handle TCP
packets with the URG flag. A remote attacker could use this to cause a
denial of service. (CVE-2017-6214)

Andrey Konovalov discovered that the LLC subsystem in the Linux kernel did
not properly set up a destructor in certain situations. A local attacker
could use this to cause a denial of service (system crash). (CVE-2017-6345)

It was discovered that a race condition existed in the AF_PACKET handling
code in the Linux kernel. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2017-6346)

Andrey Konovalov discovered that the IP layer in the Linux kernel made
improper assumptions about internal data layout when performing checksums.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2017-6347)

Dmitry Vyukov discovered race conditions in the Infrared (IrDA) subsystem
in the Linux kernel. A local attacker could use this to cause a denial of
service (deadlock). (CVE-2017-6348)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gke, linux-meta, linux-meta-aws, linux-meta-gke, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
