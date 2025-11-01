# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842139");
  script_cve_id("CVE-2015-2316", "CVE-2015-2317");
  script_tag(name:"creation_date", value:"2015-03-24 06:10:35 +0000 (Tue, 24 Mar 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2539-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2539-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2539-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-2539-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrey Babak discovered that Django incorrectly handled strip_tags. A
remote attacker could possibly use this issue to cause Django to enter an
infinite loop, resulting in a denial of service. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2015-2316)

Daniel Chatfield discovered that Django incorrectly handled user-supplied
redirect URLs. A remote attacker could possibly use this issue to perform a
cross-site scripting attack. (CVE-2015-2317)");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
