# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842916");
  script_cve_id("CVE-2016-6136", "CVE-2016-6480", "CVE-2016-6828");
  script_tag(name:"creation_date", value:"2016-10-14 03:54:21 +0000 (Fri, 14 Oct 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-3097-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3097-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3097-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-3097-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marco Grassi discovered a use-after-free condition could occur in the TCP
retransmit queue handling code in the Linux kernel. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2016-6828)

Pengfei Wang discovered a race condition in the audit subsystem in the
Linux kernel. A local attacker could use this to corrupt audit logs or
disrupt system-call auditing. (CVE-2016-6136)

Pengfei Wang discovered a race condition in the Adaptec AAC RAID controller
driver in the Linux kernel when handling ioctl()s. A local attacker could
use this to cause a denial of service (system crash). (CVE-2016-6480)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
