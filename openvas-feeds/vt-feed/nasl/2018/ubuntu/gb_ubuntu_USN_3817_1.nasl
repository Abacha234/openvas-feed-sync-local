# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843817");
  script_cve_id("CVE-2018-1000030", "CVE-2018-1000802", "CVE-2018-1060", "CVE-2018-1061", "CVE-2018-14647");
  script_tag(name:"creation_date", value:"2018-11-14 05:09:22 +0000 (Wed, 14 Nov 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-07 21:14:00 +0000 (Mon, 07 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-3817-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3817-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3817-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7, python3.4, python3.5' package(s) announced via the USN-3817-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python incorrectly handled large amounts of data. A
remote attacker could use this issue to cause Python to crash, resulting in
a denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2018-1000030)

It was discovered that Python incorrectly handled running external commands
in the shutil module. A remote attacker could use this issue to cause
Python to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2018-1000802)

It was discovered that Python incorrectly used regular expressions
vulnerable to catastrophic backtracking. A remote attacker could possibly
use this issue to cause a denial of service. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2018-1060, CVE-2018-1061)

It was discovered that Python failed to initialize Expat's hash salt. A
remote attacker could possibly use this issue to cause hash collisions,
leading to a denial of service. (CVE-2018-14647)");

  script_tag(name:"affected", value:"'python2.7, python3.4, python3.5' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
