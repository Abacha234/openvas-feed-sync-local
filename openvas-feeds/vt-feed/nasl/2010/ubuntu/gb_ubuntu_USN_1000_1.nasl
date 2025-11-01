# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840523");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2009-4895", "CVE-2010-2066", "CVE-2010-2226", "CVE-2010-2248", "CVE-2010-2478", "CVE-2010-2495", "CVE-2010-2521", "CVE-2010-2524", "CVE-2010-2525", "CVE-2010-2798", "CVE-2010-2942", "CVE-2010-2946", "CVE-2010-2954", "CVE-2010-2960", "CVE-2010-2963", "CVE-2010-3015", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3080", "CVE-2010-3084", "CVE-2010-3310", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3477", "CVE-2010-3705", "CVE-2010-3904");
  script_tag(name:"creation_date", value:"2010-10-22 14:42:09 +0000 (Fri, 22 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 14:27:00 +0000 (Tue, 11 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-1000-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1000-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1000-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-ec2, linux-source-2.6.15' package(s) announced via the USN-1000-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that the RDS network protocol did not correctly
check certain parameters. A local attacker could exploit this gain root
privileges. (CVE-2010-3904)

Al Viro discovered a race condition in the TTY driver. A local attacker
could exploit this to crash the system, leading to a denial of service.
(CVE-2009-4895)

Dan Rosenberg discovered that the MOVE_EXT ext4 ioctl did not correctly
check file permissions. A local attacker could overwrite append-only files,
leading to potential data loss. (CVE-2010-2066)

Dan Rosenberg discovered that the swapexit xfs ioctl did not correctly
check file permissions. A local attacker could exploit this to read from
write-only files, leading to a loss of privacy. (CVE-2010-2226)

Suresh Jayaraman discovered that CIFS did not correctly validate certain
response packets. A remote attacker could send specially crafted traffic
that would crash the system, leading to a denial of service.
(CVE-2010-2248)

Ben Hutchings discovered that the ethtool interface did not correctly check
certain sizes. A local attacker could perform malicious ioctl calls that
could crash the system, leading to a denial of service. (CVE-2010-2478,
CVE-2010-3084)

James Chapman discovered that L2TP did not correctly evaluate checksum
capabilities. If an attacker could make malicious routing changes, they
could crash the system, leading to a denial of service. (CVE-2010-2495)

Neil Brown discovered that NFSv4 did not correctly check certain write
requests. A remote attacker could send specially crafted traffic that could
crash the system or possibly gain root privileges. (CVE-2010-2521)

David Howells discovered that DNS resolution in CIFS could be spoofed. A
local attacker could exploit this to control DNS replies, leading to a loss
of privacy and possible privilege escalation. (CVE-2010-2524)

Dan Rosenberg discovered a flaw in gfs2 file system's handling of acls
(access control lists). An unprivileged local attacker could exploit this
flaw to gain access or execute any file stored in the gfs2 file system.
(CVE-2010-2525)

Bob Peterson discovered that GFS2 rename operations did not correctly
validate certain sizes. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-2798)

Eric Dumazet discovered that many network functions could leak kernel stack
contents. A local attacker could exploit this to read portions of kernel
memory, leading to a loss of privacy. (CVE-2010-2942, CVE-2010-3477)

Sergey Vlasov discovered that JFS did not correctly handle certain extended
attributes. A local attacker could bypass namespace access rules, leading
to a loss of privacy. (CVE-2010-2946)

Tavis Ormandy discovered that the IRDA subsystem did not correctly shut
down. A local attacker could exploit this to cause the system to crash or
possibly gain root privileges. (CVE-2010-2954)

Tavis Ormandy discovered that the session ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-ec2, linux-source-2.6.15' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
