# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841544");
  script_cve_id("CVE-2013-1060", "CVE-2013-1943", "CVE-2013-2206", "CVE-2013-4162");
  script_tag(name:"creation_date", value:"2013-09-12 06:09:49 +0000 (Thu, 12 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-03 15:58:00 +0000 (Mon, 03 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-1939-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1939-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1939-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1939-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vasily Kulikov discovered a flaw in the Linux Kernel's perf tool that
allows for privilege escalation. A local user could exploit this flaw to
run commands as root when using the perf tool.
(CVE-2013-1060)

Michael S. Tsirkin discovered a flaw in how the Linux kernel's KVM
subsystem allocates memory slots for the guest's address space. A local
user could exploit this flaw to gain system privileges or obtain sensitive
information from kernel memory. (CVE-2013-1943)

A flaw was discovered in the SCTP (stream control transfer protocol)
network protocol's handling of duplicate cookies in the Linux kernel. A
remote attacker could exploit this flaw to cause a denial of service
(system crash) on another remote user querying the SCTP connection.
(CVE-2013-2206)

Hannes Frederic Sowa discovered a flaw in setsockopt UDP_CORK option in the
Linux kernel's IPv6 stack. A local user could exploit this flaw to cause a
denial of service (system crash). (CVE-2013-4162)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
