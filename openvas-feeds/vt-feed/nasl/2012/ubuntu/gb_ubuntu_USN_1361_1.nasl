# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840904");
  script_cve_id("CVE-2011-3353", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0044");
  script_tag(name:"creation_date", value:"2012-02-21 13:30:40 +0000 (Tue, 21 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-29 15:27:00 +0000 (Wed, 29 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1361-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1361-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1361-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1361-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Han-Wen Nienhuys reported a flaw in the FUSE kernel module. A local user
who can mount a FUSE file system could cause a denial of service.
(CVE-2011-3353)

A flaw was found in KVM's Programmable Interval Timer (PIT). When a virtual
interrupt control is not available a local user could use this to cause a
denial of service by starting a timer. (CVE-2011-4622)

A flaw was discovered in the XFS filesystem. If a local user mounts a
specially crafted XFS image it could potential execute arbitrary code on
the system. (CVE-2012-0038)

Chen Haogang discovered an integer overflow that could result in memory
corruption. A local unprivileged user could use this to crash the system.
(CVE-2012-0044)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
