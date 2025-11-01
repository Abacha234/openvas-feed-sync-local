# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841837");
  script_cve_id("CVE-2013-7339", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2678");
  script_tag(name:"creation_date", value:"2014-06-02 10:40:59 +0000 (Mon, 02 Jun 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2220-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2220-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2220-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-2220-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matthew Daley reported an information leak in the floppy disk driver of the
Linux kernel. An unprivileged local user could exploit this flaw to obtain
potentially sensitive information from kernel memory. (CVE-2014-1738)

Matthew Daley reported a flaw in the handling of ioctl commands by the
floppy disk driver in the Linux kernel. An unprivileged local user could
exploit this flaw to gain administrative privileges if the floppy disk
module is loaded. (CVE-2014-1737)

A flaw was discovered in the Reliable Datagram Sockets (RDS) protocol
implementation in the Linux kernel for systems that lack RDS transports. An
unprivileged local user could exploit this flaw to cause a denial of
service (system crash). (CVE-2013-7339)

An error was discovered in the Reliable Datagram Sockets (RDS) protocol
stack in the Linux kernel. A local user could exploit this flaw to cause a
denial of service (system crash) or possibly have unspecified other impact.
(CVE-2014-2678)");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
