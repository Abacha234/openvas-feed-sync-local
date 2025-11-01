# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840611");
  script_cve_id("CVE-2010-4075", "CVE-2010-4158", "CVE-2010-4163", "CVE-2010-4668");
  script_tag(name:"creation_date", value:"2011-03-15 13:58:18 +0000 (Tue, 15 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1086-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1086-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1086-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-1086-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that multiple terminal ioctls did not correctly
initialize structure memory. A local attacker could exploit this to read
portions of kernel stack memory, leading to a loss of privacy.
(CVE-2010-4075)

Dan Rosenberg discovered that the socket filters did not correctly
initialize structure memory. A local attacker could create malicious
filters to read portions of kernel stack memory, leading to a loss of
privacy. (CVE-2010-4158)

Dan Rosenberg discovered that the SCSI subsystem did not correctly validate
iov segments. A local attacker with access to a SCSI device could send
specially crafted requests to crash the system, leading to a denial of
service. (CVE-2010-4163, CVE-2010-4668)");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
