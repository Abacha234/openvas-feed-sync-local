# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843983");
  script_cve_id("CVE-2018-16877", "CVE-2018-16878", "CVE-2019-3885");
  script_tag(name:"creation_date", value:"2019-04-24 02:00:54 +0000 (Wed, 24 Apr 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-07 01:15:00 +0000 (Thu, 07 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-3952-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3952-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3952-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pacemaker' package(s) announced via the USN-3952-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan Pokorny discovered that Pacemaker incorrectly handled client-server
authentication. A local attacker could possibly use this issue to escalate
privileges. (CVE-2018-16877)

Jan Pokorny discovered that Pacemaker incorrectly handled certain
verifications. A local attacker could possibly use this issue to cause a
denial of service. (CVE-2018-16878)

Jan Pokorny discovered that Pacemaker incorrectly handled certain memory
operations. A local attacker could possibly use this issue to obtain
sensitive information in log outputs. This issue only applied to Ubuntu
18.04 LTS, Ubuntu 18.10, and Ubuntu 19.04. (CVE-2019-3885)");

  script_tag(name:"affected", value:"'pacemaker' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
