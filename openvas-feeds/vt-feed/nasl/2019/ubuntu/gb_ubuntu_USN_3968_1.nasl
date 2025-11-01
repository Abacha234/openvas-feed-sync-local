# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843993");
  script_cve_id("CVE-2016-7076", "CVE-2017-1000368");
  script_tag(name:"creation_date", value:"2019-05-07 02:00:31 +0000 (Tue, 07 May 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-29 19:29:00 +0000 (Wed, 29 May 2019)");

  script_name("Ubuntu: Security Advisory (USN-3968-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3968-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3968-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the USN-3968-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer discovered that Sudo incorrectly handled the noexec
restriction when used with certain applications. A local attacker could
possibly use this issue to bypass configured restrictions and execute
arbitrary commands. (CVE-2016-7076)

It was discovered that Sudo did not properly parse the contents of
/proc/[pid]/stat when attempting to determine its controlling tty. A local
attacker in some configurations could possibly use this to overwrite any
file on the filesystem, bypassing intended permissions. (CVE-2017-1000368)");

  script_tag(name:"affected", value:"'sudo' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
