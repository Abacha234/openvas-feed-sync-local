# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843980");
  script_tag(name:"creation_date", value:"2019-04-18 02:00:52 +0000 (Thu, 18 Apr 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3914-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3914-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3914-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1821250");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntfs-3g' package(s) announced via the USN-3914-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3914-1 fixed vulnerabilities in NTFS-3G. As an additional hardening
measure, this update removes the setuid bit from the ntfs-3g binary.

Original advisory details:

 A heap buffer overflow was discovered in NTFS-3G when executing it with a
 relative mount point path that is too long. A local attacker could
 potentially exploit this to execute arbitrary code as the administrator.");

  script_tag(name:"affected", value:"'ntfs-3g' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
