# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842998");
  script_cve_id("CVE-2016-6213", "CVE-2016-8630", "CVE-2016-8633", "CVE-2016-8645", "CVE-2016-9313", "CVE-2016-9555");
  script_tag(name:"creation_date", value:"2016-12-21 04:45:13 +0000 (Wed, 21 Dec 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-13 21:47:00 +0000 (Mon, 13 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-3162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3162-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3162-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta' package(s) announced via the USN-3162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CAI Qian discovered that shared bind mounts in a mount namespace
exponentially added entries without restriction to the Linux kernel's mount
table. A local attacker could use this to cause a denial of service (system
crash). (CVE-2016-6213)

It was discovered that the KVM implementation for x86/x86_64 in the Linux
kernel could dereference a null pointer. An attacker in a guest virtual
machine could use this to cause a denial of service (system crash) in the
KVM host. (CVE-2016-8630)

Eyal Itkin discovered that the IP over IEEE 1394 (FireWire) implementation
in the Linux kernel contained a buffer overflow when handling fragmented
packets. A remote attacker could use this to possibly execute arbitrary
code with administrative privileges. (CVE-2016-8633)

Marco Grassi discovered that the TCP implementation in the Linux kernel
mishandles socket buffer (skb) truncation. A local attacker could use this
to cause a denial of service (system crash). (CVE-2016-8645)

It was discovered that the keyring implementation in the Linux kernel
improperly handled crypto registration in conjunction with successful key-
type registration. A local attacker could use this to cause a denial of
service (system crash). (CVE-2016-9313)

Andrey Konovalov discovered that the SCTP implementation in the Linux
kernel improperly handled validation of incoming data. A remote attacker
could use this to cause a denial of service (system crash). (CVE-2016-9555)");

  script_tag(name:"affected", value:"'linux, linux-meta' package(s) on Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
