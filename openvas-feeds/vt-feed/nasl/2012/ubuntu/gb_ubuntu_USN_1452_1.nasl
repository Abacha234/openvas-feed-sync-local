# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841018");
  script_cve_id("CVE-2012-1601", "CVE-2012-2123", "CVE-2012-2745");
  script_tag(name:"creation_date", value:"2012-05-28 05:30:16 +0000 (Mon, 28 May 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1452-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1452-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1452-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1452-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Linux kernel's KVM (Kernel Virtual Machine) virtual
cpu setup. An unprivileged local user could exploit this flaw to crash the
system leading to a denial of service. (CVE-2012-1601)

Steve Grubb reported a flaw with Linux fscaps (file system base
capabilities) when used to increase the permissions of a process. For
application on which fscaps are in use a local attacker can disable address
space randomization to make attacking the process with raised privileges
easier. (CVE-2012-2123)

A flaw was found in how the Linux kernel passed the replacement session
keyring to a child process. An unprivileged local user could exploit this
flaw to cause a denial of service (panic). (CVE-2012-2745)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
