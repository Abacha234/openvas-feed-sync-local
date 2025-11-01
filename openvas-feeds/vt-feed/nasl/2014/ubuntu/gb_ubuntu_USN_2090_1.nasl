# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841695");
  script_cve_id("CVE-2013-6048", "CVE-2013-6359");
  script_tag(name:"creation_date", value:"2014-01-30 05:15:48 +0000 (Thu, 30 Jan 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2090-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2090-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'munin' package(s) announced via the USN-2090-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christoph Biedl discovered that Munin incorrectly handled certain
multigraph data. A remote attacker could use this issue to cause Munin to
consume resources, resulting in a denial of service. (CVE-2013-6048)

Christoph Biedl discovered that Munin incorrectly handled certain
multigraph service names. A remote attacker could use this issue to cause
Munin to stop data collection, resulting in a denial of service.
(CVE-2013-6359)");

  script_tag(name:"affected", value:"'munin' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
