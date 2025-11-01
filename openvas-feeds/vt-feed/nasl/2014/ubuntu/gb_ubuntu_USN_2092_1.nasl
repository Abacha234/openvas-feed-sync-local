# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841701");
  script_cve_id("CVE-2013-4344", "CVE-2013-4375", "CVE-2013-4377");
  script_tag(name:"creation_date", value:"2014-02-03 08:40:54 +0000 (Mon, 03 Feb 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2092-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2092-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2092-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu, qemu-kvm' package(s) announced via the USN-2092-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Asias He discovered that QEMU incorrectly handled SCSI controllers with
more than 256 attached devices. A local user could possibly use this flaw
to elevate privileges. (CVE-2013-4344)

It was discovered that QEMU incorrectly handled Xen disks. A local guest
could possibly use this flaw to consume resources, resulting in a denial of
service. This issue only affected Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4375)

Sibiao Luo discovered that QEMU incorrectly handled device hot-unplugging.
A local user could possibly use this flaw to cause a denial of service.
This issue only affected Ubuntu 13.10. (CVE-2013-4377)");

  script_tag(name:"affected", value:"'qemu, qemu-kvm' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
