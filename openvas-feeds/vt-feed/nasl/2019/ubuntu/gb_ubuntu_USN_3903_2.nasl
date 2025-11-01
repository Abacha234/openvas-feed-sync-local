# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843927");
  script_cve_id("CVE-2018-16880", "CVE-2018-18397", "CVE-2019-6133");
  script_tag(name:"creation_date", value:"2019-03-07 03:12:04 +0000 (Thu, 07 Mar 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-16 15:29:00 +0000 (Thu, 16 May 2019)");

  script_name("Ubuntu: Security Advisory (USN-3903-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3903-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3903-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-hwe, linux-meta-azure, linux-meta-hwe, linux-signed-azure, linux-signed-hwe' package(s) announced via the USN-3903-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3903-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.10.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 18.10 for Ubuntu 18.04 LTS.

Jason Wang discovered that the vhost net driver in the Linux kernel
contained an out of bounds write vulnerability. An attacker in a guest
virtual machine could use this to cause a denial of service (host system
crash) or possibly execute arbitrary code in the host kernel.
(CVE-2018-16880)

Jann Horn discovered that the userfaultd implementation in the Linux kernel
did not properly restrict access to certain ioctls. A local attacker could
use this possibly to modify files. (CVE-2018-18397)

Jann Horn discovered a race condition in the fork() system call in the
Linux kernel. A local attacker could use this to gain access to services
that cache authorizations. (CVE-2019-6133)");

  script_tag(name:"affected", value:"'linux-azure, linux-hwe, linux-meta-azure, linux-meta-hwe, linux-signed-azure, linux-signed-hwe' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
