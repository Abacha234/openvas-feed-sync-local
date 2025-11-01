# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842056");
  script_cve_id("CVE-2013-6435", "CVE-2014-8118");
  script_tag(name:"creation_date", value:"2015-01-23 11:58:40 +0000 (Fri, 23 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2479-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2479-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2479-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rpm' package(s) announced via the USN-2479-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer discovered that RPM incorrectly handled temporary files. A
local attacker could use this issue to execute arbitrary code.
(CVE-2013-6435)

Florian Weimer discovered that RPM incorrectly handled certain CPIO
headers. If a user or automated system were tricked into installing a
malicious package file, a remote attacker could use this issue to cause RPM
to crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2014-8118)");

  script_tag(name:"affected", value:"'rpm' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
