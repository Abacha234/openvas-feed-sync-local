# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840793");
  script_cve_id("CVE-2011-2213", "CVE-2011-2497", "CVE-2011-2695", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191");
  script_tag(name:"creation_date", value:"2011-10-31 12:45:00 +0000 (Mon, 31 Oct 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 10:59:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1246-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1246-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1246-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1246-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that the IPv4 diagnostic routines did not
correctly validate certain requests. A local attacker could exploit this to
consume CPU resources, leading to a denial of service. (CVE-2011-2213)

Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
certain L2CAP requests. If a system was using Bluetooth, a remote attacker
could send specially crafted traffic to crash the system or gain root
privileges. (CVE-2011-2497)

It was discovered that the EXT4 filesystem contained multiple off-by-one
flaws. A local attacker could exploit this to crash the system, leading to
a denial of service. (CVE-2011-2695)

Mauro Carvalho Chehab discovered that the si4713 radio driver did not
correctly check the length of memory copies. If this hardware was
available, a local attacker could exploit this to crash the system or gain
root privileges. (CVE-2011-2700)

Herbert Xu discovered that certain fields were incorrectly handled when
Generic Receive Offload (CVE-2011-2723)

Time Warns discovered that long symlinks were incorrectly handled on Be
filesystems. A local attacker could exploit this with a malformed Be
filesystem and crash the system, leading to a denial of service.
(CVE-2011-2928)

Dan Kaminsky discovered that the kernel incorrectly handled random sequence
number generation. An attacker could use this flaw to possibly predict
sequence numbers and inject packets. (CVE-2011-3188)

Darren Lavender discovered that the CIFS client incorrectly handled certain
large values. A remote attacker with a malicious server could exploit this
to crash the system or possibly execute arbitrary code as the root user.
(CVE-2011-3191)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
