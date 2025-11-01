# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840663");
  script_cve_id("CVE-2010-4342", "CVE-2010-4527", "CVE-2010-4529", "CVE-2011-0521");
  script_tag(name:"creation_date", value:"2011-06-03 07:20:26 +0000 (Fri, 03 Jun 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1133-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1133-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1133-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1133-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nelson Elhage discovered that Econet did not correctly handle AUN packets
over UDP. A local attacker could send specially crafted traffic to crash
the system, leading to a denial of service. (CVE-2010-4342)

Dan Rosenberg discovered that the OSS subsystem did not handle name
termination correctly. A local attacker could exploit this crash the system
or gain root privileges. (CVE-2010-4527)

Dan Rosenberg discovered that IRDA did not correctly check the size of
buffers. On non-x86 systems, a local attacker could exploit this to read
kernel heap memory, leading to a loss of privacy. (CVE-2010-4529)

Dan Carpenter discovered that the TTPCI DVB driver did not check certain
values during an ioctl. If the dvb-ttpci module was loaded, a local
attacker could exploit this to crash the system, leading to a denial of
service, or possibly gain root privileges. (CVE-2011-0521)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
