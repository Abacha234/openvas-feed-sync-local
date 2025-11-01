# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842629");
  script_cve_id("CVE-2013-7446", "CVE-2015-7513", "CVE-2015-7990", "CVE-2015-8374", "CVE-2015-8787");
  script_tag(name:"creation_date", value:"2016-02-05 07:44:43 +0000 (Fri, 05 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-31 17:53:00 +0000 (Mon, 31 Jan 2022)");

  script_name("Ubuntu: Security Advisory (USN-2889-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2889-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2889-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2889-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a use-after-free vulnerability existed in the
AF_UNIX implementation in the Linux kernel. A local attacker could use
crafted epoll_ctl calls to cause a denial of service (system crash) or
expose sensitive information. (CVE-2013-7446)

It was discovered that the KVM implementation in the Linux kernel did not
properly restore the values of the Programmable Interrupt Timer (PIT). A
user-assisted attacker in a KVM guest could cause a denial of service in
the host (system crash). (CVE-2015-7513)

Sasha Levin discovered that the Reliable Datagram Sockets (RDS)
implementation in the Linux kernel had a race condition when checking
whether a socket was bound or not. A local attacker could use this to cause
a denial of service (system crash). (CVE-2015-7990)

It was discovered that the Btrfs implementation in the Linux kernel
incorrectly handled compressed inline extants on truncation. A local
attacker could use this to expose sensitive information. (CVE-2015-8374)

It was discovered that the netfilter Network Address Translation (NAT)
implementation did not ensure that data structures were initialized when
handling IPv4 addresses. An attacker could use this to cause a denial of
service (system crash). (CVE-2015-8787)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
