# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843194");
  script_cve_id("CVE-2014-3248", "CVE-2017-2295");
  script_tag(name:"creation_date", value:"2017-06-06 04:27:24 +0000 (Tue, 06 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-16 12:22:00 +0000 (Tue, 16 Jul 2019)");

  script_name("Ubuntu: Security Advisory (USN-3308-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3308-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3308-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puppet' package(s) announced via the USN-3308-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dennis Rowe discovered that Puppet incorrectly handled the search path. A
local attacker could use this issue to possibly execute arbitrary code.
(CVE-2014-3248)

It was discovered that Puppet incorrectly handled YAML deserialization. A
remote attacker could possibly use this issue to execute arbitrary code on
the master. This update is incompatible with agents older than 3.2.2.
(CVE-2017-2295)");

  script_tag(name:"affected", value:"'puppet' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
