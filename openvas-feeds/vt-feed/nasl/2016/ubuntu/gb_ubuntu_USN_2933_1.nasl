# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842695");
  script_cve_id("CVE-2014-2972", "CVE-2016-1531");
  script_tag(name:"creation_date", value:"2016-03-16 05:09:39 +0000 (Wed, 16 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)");

  script_name("Ubuntu: Security Advisory (USN-2933-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2933-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2933-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exim4' package(s) announced via the USN-2933-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Exim incorrectly filtered environment variables when
used with the perl_startup configuration option. If the perl_startup option
was enabled, a local attacker could use this issue to escalate their
privileges to the root user. This issue has been fixed by having Exim clean
the complete execution environment by default on startup, including any
subprocesses such as transports that call other programs. This change in
behaviour may break existing installations and can be adjusted by using two
new configuration options, keep_environment and add_environment.
(CVE-2016-1531)

Patrick William discovered that Exim incorrectly expanded mathematical
comparisons twice. A local attacker could possibly use this issue to
perform arbitrary file operations as the Exim user. This issue only
affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-2972)");

  script_tag(name:"affected", value:"'exim4' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
