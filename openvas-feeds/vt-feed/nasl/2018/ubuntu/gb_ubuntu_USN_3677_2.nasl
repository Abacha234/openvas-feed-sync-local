# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843554");
  script_cve_id("CVE-2018-1068", "CVE-2018-1092", "CVE-2018-7492", "CVE-2018-8087", "CVE-2018-8781");
  script_tag(name:"creation_date", value:"2018-06-12 03:55:36 +0000 (Tue, 12 Jun 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-28 01:03:00 +0000 (Thu, 28 Feb 2019)");

  script_name("Ubuntu: Security Advisory (USN-3677-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3677-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3677-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp, linux-hwe, linux-meta-gcp, linux-meta-hwe, linux-meta-oem, linux-oem' package(s) announced via the USN-3677-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3677-1 fixed vulnerabilities in the Linux kernel for Ubuntu 17.10.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 17.10 for Ubuntu 16.04 LTS.

It was discovered that the netfilter subsystem of the Linux kernel did not
properly validate ebtables offsets. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-1068)

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly handle corrupted meta data in some situations. An
attacker could use this to specially craft an ext4 file system that caused
a denial of service (system crash) when mounted. (CVE-2018-1092)

It was discovered that a NULL pointer dereference existed in the RDS
(Reliable Datagram Sockets) protocol implementation in the Linux kernel. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2018-7492)

It was discovered that the 802.11 software simulator implementation in the
Linux kernel contained a memory leak when handling certain error
conditions. A local attacker could possibly use this to cause a denial of
service (memory exhaustion). (CVE-2018-8087)

Eyal Itkin discovered that the USB displaylink video adapter driver in the
Linux kernel did not properly validate mmap offsets sent from userspace. A
local attacker could use this to expose sensitive information (kernel
memory) or possibly execute arbitrary code. (CVE-2018-8781)");

  script_tag(name:"affected", value:"'linux-gcp, linux-hwe, linux-meta-gcp, linux-meta-hwe, linux-meta-oem, linux-oem' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
