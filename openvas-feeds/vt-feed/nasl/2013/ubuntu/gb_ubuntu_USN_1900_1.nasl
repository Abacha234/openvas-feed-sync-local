# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841495");
  script_cve_id("CVE-2012-4508", "CVE-2012-6657", "CVE-2013-2141", "CVE-2013-2852");
  script_tag(name:"creation_date", value:"2013-07-05 07:46:52 +0000 (Fri, 05 Jul 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1900-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1900-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1900-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-1900-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dmitry Monakhov reported a race condition flaw the Linux ext4 filesystem
that can expose stale data. An unprivileged user could exploit this flaw to
cause an information leak. (CVE-2012-4508)

Dave Jones discovered that the Linux kernel's socket subsystem does not
correctly ensure the keepalive action is associated with a stream socket. A
local user could exploit this flaw to cause a denial of service (system
crash) by creating a raw socket. (CVE-2012-6657)

An information leak was discovered in the Linux kernel's tkill and tgkill
system calls when used from compat processes. A local user could exploit
this flaw to examine potentially sensitive kernel memory. (CVE-2013-2141)

Kees Cook discovered a format string vulnerability in the Broadcom B43
wireless driver for the Linux kernel. A local user could exploit this flaw
to gain administrative privileges. (CVE-2013-2852)");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
