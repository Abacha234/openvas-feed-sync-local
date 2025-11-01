# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840990");
  script_cve_id("CVE-2011-4347", "CVE-2012-0045", "CVE-2012-1090", "CVE-2012-1097", "CVE-2012-4398");
  script_tag(name:"creation_date", value:"2012-04-26 05:06:27 +0000 (Thu, 26 Apr 2012)");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 20:14:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1426-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1426-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1426-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-1426-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sasha Levin discovered a flaw in the permission checking for device
assignments requested via the kvm ioctl in the Linux kernel. A local user
could use this flaw to crash the system causing a denial of service.
(CVE-2011-4347)

Stephan Barwolf discovered a flaw in the KVM (kernel-based virtual
machine) subsystem of the Linux kernel. A local unprivileged user can crash
use this flaw to crash VMs causing a deny of service. (CVE-2012-0045)

A flaw was discovered in the Linux kernel's cifs file system. An
unprivileged local user could exploit this flaw to crash the system leading
to a denial of service. (CVE-2012-1090)

H. Peter Anvin reported a flaw in the Linux kernel that could crash the
system. A local user could exploit this flaw to crash the system.
(CVE-2012-1097)

Tetsuo Handa reported a flaw in the OOM (out of memory) killer of the Linux
kernel. A local unprivileged user can exploit this flaw to cause system
instability and denial of services. (CVE-2012-4398)");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
