# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843506");
  script_cve_id("CVE-2017-13305", "CVE-2017-16538", "CVE-2018-1000004", "CVE-2018-5750", "CVE-2018-7566");
  script_tag(name:"creation_date", value:"2018-04-25 06:36:58 +0000 (Wed, 25 Apr 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3631-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3631-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3631-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-lts-xenial, linux-meta-aws, linux-meta-lts-xenial' package(s) announced via the USN-3631-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3631-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

It was discovered that a buffer overread vulnerability existed in the
keyring subsystem of the Linux kernel. A local attacker could possibly use
this to expose sensitive information (kernel memory). (CVE-2017-13305)

It was discovered that the DM04/QQBOX USB driver in the Linux kernel did
not properly handle device attachment and warm-start. A physically
proximate attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2017-16538)

Luo Quan and Wei Yang discovered that a race condition existed in the
Advanced Linux Sound Architecture (ALSA) subsystem of the Linux kernel when
handling ioctl()s. A local attacker could use this to cause a denial of
service (system deadlock). (CVE-2018-1000004)

Wang Qize discovered that an information disclosure vulnerability existed
in the SMBus driver for ACPI Embedded Controllers in the Linux kernel. A
local attacker could use this to expose sensitive information (kernel
pointer addresses). (CVE-2018-5750)

Fan Long Fei discovered that a race condition existed in the Advanced Linux
Sound Architecture (ALSA) subsystem of the Linux kernel that could lead to
a use-after-free or an out-of-bounds buffer access. A local attacker with
access to /dev/snd/seq could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-7566)");

  script_tag(name:"affected", value:"'linux-aws, linux-lts-xenial, linux-meta-aws, linux-meta-lts-xenial' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
