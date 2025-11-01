# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843005");
  script_cve_id("CVE-2016-6213", "CVE-2016-7916");
  script_tag(name:"creation_date", value:"2016-12-21 04:45:57 +0000 (Wed, 21 Dec 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-18 02:59:00 +0000 (Wed, 18 Jan 2017)");

  script_name("Ubuntu: Security Advisory (USN-3160-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3160-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3160-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty, linux-meta-lts-trusty' package(s) announced via the USN-3160-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3160-1 fixed vulnerabilities in the Linux kernel for Ubuntu 14.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 14.04 LTS for Ubuntu
12.04 LTS.

CAI Qian discovered that shared bind mounts in a mount namespace
exponentially added entries without restriction to the Linux kernel's mount
table. A local attacker could use this to cause a denial of service (system
crash). (CVE-2016-6213)

It was discovered that a race condition existed in the procfs
environ_read function in the Linux kernel, leading to an integer
underflow. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2016-7916)");

  script_tag(name:"affected", value:"'linux-lts-trusty, linux-meta-lts-trusty' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
