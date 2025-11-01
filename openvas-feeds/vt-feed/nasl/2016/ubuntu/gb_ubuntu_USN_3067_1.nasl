# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842869");
  script_cve_id("CVE-2015-8947", "CVE-2016-2052");
  script_tag(name:"creation_date", value:"2016-08-25 03:40:32 +0000 (Thu, 25 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-3067-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3067-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3067-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'harfbuzz' package(s) announced via the USN-3067-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kostya Serebryany discovered that HarfBuzz incorrectly handled memory. A
remote attacker could use this issue to cause HarfBuzz to crash, resulting
in a denial of service, or possibly execute arbitrary code. (CVE-2015-8947)

It was discovered that HarfBuzz incorrectly handled certain length checks.
A remote attacker could use this issue to cause HarfBuzz to crash,
resulting in a denial of service, or possibly execute arbitrary code.
This issue only applied to Ubuntu 16.04 LTS. (CVE-2016-2052)");

  script_tag(name:"affected", value:"'harfbuzz' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
