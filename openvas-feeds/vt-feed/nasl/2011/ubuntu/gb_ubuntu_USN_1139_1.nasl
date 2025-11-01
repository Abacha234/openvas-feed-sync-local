# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840669");
  script_cve_id("CVE-2010-3762", "CVE-2011-1910");
  script_tag(name:"creation_date", value:"2011-06-06 14:56:27 +0000 (Mon, 06 Jun 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-1139-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1139-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1139-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-1139-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Bind incorrectly handled certain bad signatures if
multiple trust anchors existed for a single zone. A remote attacker could
use this flaw to cause Bind to stop responding, resulting in a denial of
service. This issue only affected Ubuntu 8.04 LTS and 10.04 LTS.
(CVE-2010-3762)

Frank Kloeker and Michael Sinatra discovered that Bind incorrectly handled
certain very large RRSIG RRsets included in negative responses. A remote
attacker could use this flaw to cause Bind to stop responding, resulting in
a denial of service. (CVE-2011-1910)");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
