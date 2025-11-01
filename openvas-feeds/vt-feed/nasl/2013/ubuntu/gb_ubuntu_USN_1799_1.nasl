# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841396");
  script_cve_id("CVE-2013-0131");
  script_tag(name:"creation_date", value:"2013-04-15 04:50:44 +0000 (Mon, 15 Apr 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1799-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1799-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1799-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia-graphics-drivers, nvidia-graphics-drivers-updates, nvidia-settings, nvidia-settings-updates' package(s) announced via the USN-1799-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the NVIDIA graphics drivers incorrectly handled
large ARGB cursors. A local attacker could use this issue to gain root
privileges.

The NVIDIA graphics drivers have been updated to 304.88 to fix this issue.
In addition to the security fix, the updated packages contain bug fixes,
new features, and possibly incompatible changes.");

  script_tag(name:"affected", value:"'nvidia-graphics-drivers, nvidia-graphics-drivers-updates, nvidia-settings, nvidia-settings-updates' package(s) on Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
