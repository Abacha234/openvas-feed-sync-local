# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843331");
  script_cve_id("CVE-2017-12134", "CVE-2017-14106", "CVE-2017-14140");
  script_tag(name:"creation_date", value:"2017-10-11 07:57:43 +0000 (Wed, 11 Oct 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3444-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3444-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3444-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gke, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gke, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) announced via the USN-3444-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan H. Schonherr discovered that the Xen subsystem did not properly handle
block IO merges correctly in some situations. An attacker in a guest vm
could use this to cause a denial of service (host crash) or possibly gain
administrative privileges in the host. (CVE-2017-12134)

Andrey Konovalov discovered that a divide-by-zero error existed in the TCP
stack implementation in the Linux kernel. A local attacker could use this
to cause a denial of service (system crash). (CVE-2017-14106)

Otto Ebeling discovered that the memory manager in the Linux kernel did not
properly check the effective UID in some situations. A local attacker could
use this to expose sensitive information. (CVE-2017-14140)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gke, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gke, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
