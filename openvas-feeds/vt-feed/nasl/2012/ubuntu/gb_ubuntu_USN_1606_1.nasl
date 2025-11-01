# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841188");
  script_cve_id("CVE-2012-2137", "CVE-2012-2745");
  script_tag(name:"creation_date", value:"2012-10-12 03:50:41 +0000 (Fri, 12 Oct 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1606-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1606-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1606-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1606-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in how the Linux kernel's KVM (Kernel-based Virtual
Machine) subsystem handled MSI (Message Signaled Interrupts). A local
unprivileged user could exploit this flaw to cause a denial of service or
potentially elevate privileges. (CVE-2012-2137)

A flaw was found in how the Linux kernel passed the replacement session
keyring to a child process. An unprivileged local user could exploit this
flaw to cause a denial of service (panic). (CVE-2012-2745)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
