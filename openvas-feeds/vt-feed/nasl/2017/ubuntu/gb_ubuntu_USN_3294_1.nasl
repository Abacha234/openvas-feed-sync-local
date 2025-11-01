# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843174");
  script_cve_id("CVE-2016-0634", "CVE-2016-7543", "CVE-2016-9401", "CVE-2017-5932");
  script_tag(name:"creation_date", value:"2017-05-18 04:50:06 +0000 (Thu, 18 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-3294-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3294-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3294-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bash' package(s) announced via the USN-3294-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bernd Dietzel discovered that Bash incorrectly expanded the hostname when
displaying the prompt. If a remote attacker were able to modify a hostname,
this flaw could be exploited to execute arbitrary code. This issue only
affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2016-0634)

It was discovered that Bash incorrectly handled the SHELLOPTS and PS4
environment variables. A local attacker could use this issue to execute
arbitrary code with root privileges. This issue only affected Ubuntu 14.04
LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-7543)

It was discovered that Bash incorrectly handled the popd command. A remote
attacker could possibly use this issue to bypass restricted shells.
(CVE-2016-9401)

It was discovered that Bash incorrectly handled path autocompletion. A
local attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 17.04. (CVE-2017-5932)");

  script_tag(name:"affected", value:"'bash' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
