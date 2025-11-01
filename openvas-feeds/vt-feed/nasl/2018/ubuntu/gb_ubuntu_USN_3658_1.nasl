# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843536");
  script_cve_id("CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126");
  script_tag(name:"creation_date", value:"2018-05-24 03:46:04 +0000 (Thu, 24 May 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-30 13:15:00 +0000 (Tue, 30 Jul 2019)");

  script_name("Ubuntu: Security Advisory (USN-3658-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3658-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3658-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'procps' package(s) announced via the USN-3658-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the procps-ng top utility incorrectly read its
configuration file from the current working directory. A local attacker
could possibly use this issue to escalate privileges. (CVE-2018-1122)

It was discovered that the procps-ng ps tool incorrectly handled memory. A
local user could possibly use this issue to cause a denial of service.
(CVE-2018-1123)

It was discovered that libprocps incorrectly handled the file2strvec()
function. A local attacker could possibly use this to execute arbitrary
code. (CVE-2018-1124)

It was discovered that the procps-ng pgrep utility incorrectly handled
memory. A local attacker could possibly use this issue to cause de denial
of service. (CVE-2018-1125)

It was discovered that procps-ng incorrectly handled memory. A local
attacker could use this issue to cause a denial of service, or possibly
execute arbitrary code. (CVE-2018-1126)");

  script_tag(name:"affected", value:"'procps' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
