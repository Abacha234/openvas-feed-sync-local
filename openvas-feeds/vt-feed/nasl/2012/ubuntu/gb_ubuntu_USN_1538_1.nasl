# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841115");
  script_cve_id("CVE-2012-2136", "CVE-2012-2372", "CVE-2012-2390");
  script_tag(name:"creation_date", value:"2012-08-17 04:52:01 +0000 (Fri, 17 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1538-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1538-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1538-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-backport-natty' package(s) announced via the USN-1538-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An error was discovered in the Linux kernel's network TUN/TAP device
implementation. A local user with access to the TUN/TAP interface (which is
not available to unprivileged users until granted by a root user) could
exploit this flaw to crash the system or potential gain administrative
privileges. (CVE-2012-2136)

A flaw was found in the Linux kernel's Reliable Datagram Sockets (RDS)
protocol implementation. A local, unprivileged user could use this flaw to
cause a denial of service. (CVE-2012-2372)

An error was discovered in the Linux kernel's memory subsystem (hugetlb).
An unprivileged local user could exploit this flaw to cause a denial of
service (crash the system). (CVE-2012-2390)");

  script_tag(name:"affected", value:"'linux-lts-backport-natty' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
