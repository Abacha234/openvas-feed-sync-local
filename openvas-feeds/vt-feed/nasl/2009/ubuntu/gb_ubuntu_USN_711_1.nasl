# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63306");
  script_cve_id("CVE-2008-5905", "CVE-2008-5906");
  script_tag(name:"creation_date", value:"2009-02-02 22:28:24 +0000 (Mon, 02 Feb 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-711-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-711-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-711-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ktorrent' package(s) announced via the USN-711-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that KTorrent did not properly restrict access when using the
web interface plugin. A remote attacker could use a crafted http request and
upload arbitrary torrent files to trigger the start of downloads and seeding.
(CVE-2008-5905)

It was discovered that KTorrent did not properly handle certain parameters when
using the web interface plugin. A remote attacker could use crafted http
requests to execute arbitrary PHP code. (CVE-2008-5906)");

  script_tag(name:"affected", value:"'ktorrent' package(s) on Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
