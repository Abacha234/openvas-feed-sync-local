# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842135");
  script_cve_id("CVE-2014-8117", "CVE-2014-9705", "CVE-2015-0273", "CVE-2015-2301");
  script_tag(name:"creation_date", value:"2015-03-19 04:52:51 +0000 (Thu, 19 Mar 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2535-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2535-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2535-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-2535-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thomas Jarosch discovered that PHP incorrectly limited recursion in the
fileinfo extension. A remote attacker could possibly use this issue to
cause PHP to consume resources or crash, resulting in a denial of service.
(CVE-2014-8117)

S. Paraschoudis discovered that PHP incorrectly handled memory in the
enchant binding. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2014-9705)

Taoguang Chen discovered that PHP incorrectly handled unserializing
objects. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-0273)

It was discovered that PHP incorrectly handled memory in the phar
extension. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-2301)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
