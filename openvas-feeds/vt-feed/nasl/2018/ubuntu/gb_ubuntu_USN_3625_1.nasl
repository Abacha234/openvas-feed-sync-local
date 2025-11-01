# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843504");
  script_cve_id("CVE-2015-8853", "CVE-2016-6185", "CVE-2017-6512", "CVE-2018-6797", "CVE-2018-6798", "CVE-2018-6913");
  script_tag(name:"creation_date", value:"2018-04-17 06:32:55 +0000 (Tue, 17 Apr 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3625-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3625-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3625-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the USN-3625-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Perl incorrectly handled certain regular
expressions. An attacker could possibly use this issue to cause Perl to
hang, resulting in a denial of service. This issue only affected Ubuntu
14.04 LTS. (CVE-2015-8853)

It was discovered that Perl incorrectly loaded libraries from the current
working directory. A local attacker could possibly use this issue to
execute arbitrary code. This issue only affected Ubuntu 14.04 LTS and
Ubuntu 16.04 LTS. (CVE-2016-6185)

It was discovered that Perl incorrectly handled the rmtree and remove_tree
functions. A local attacker could possibly use this issue to set the mode
on arbitrary files. This issue only affected Ubuntu 14.04 LTS and Ubuntu
16.04 LTS. (CVE-2017-6512)

Brian Carpenter discovered that Perl incorrectly handled certain regular
expressions. An attacker could use this issue to cause Perl to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue has only been addressed in Ubuntu 16.04 LTS and Ubuntu 17.10.
(CVE-2018-6797)

Nguyen Duc Manh discovered that Perl incorrectly handled certain regular
expressions. An attacker could use this issue to cause Perl to crash,
resulting in a denial of service. This issue only affected Ubuntu 16.04 LTS
and Ubuntu 17.10. (CVE-2018-6798)

GwanYeong Kim discovered that Perl incorrectly handled certain data when
using the pack function. An attacker could use this issue to cause Perl to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2018-6913)");

  script_tag(name:"affected", value:"'perl' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
