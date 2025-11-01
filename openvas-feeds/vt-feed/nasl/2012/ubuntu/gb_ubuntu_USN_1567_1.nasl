# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841147");
  script_cve_id("CVE-2012-2745", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-3511");
  script_tag(name:"creation_date", value:"2012-09-17 11:25:00 +0000 (Mon, 17 Sep 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1567-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1567-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1567-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1567-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in how the Linux kernel passed the replacement session
keyring to a child process. An unprivileged local user could exploit this
flaw to cause a denial of service (panic). (CVE-2012-2745)

Ben Hutchings reported a flaw in the Linux kernel with some network drivers
that support TSO (TCP segment offload). A local or peer user could exploit
this flaw to cause a denial of service. (CVE-2012-3412)

Jay Fenlason and Doug Ledford discovered a bug in the Linux kernel
implementation of RDS sockets. A local unprivileged user could potentially
use this flaw to read privileged information from the kernel.
(CVE-2012-3430)

A flaw was discovered in the madvise feature of the Linux kernel's memory
subsystem. An unprivileged local use could exploit the flaw to cause a
denial of service (crash the system). (CVE-2012-3511)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
