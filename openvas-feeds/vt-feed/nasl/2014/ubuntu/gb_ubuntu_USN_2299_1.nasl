# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841915");
  script_cve_id("CVE-2014-0117", "CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");
  script_tag(name:"creation_date", value:"2014-07-28 11:11:33 +0000 (Mon, 28 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2299-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2299-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2299-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-2299-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marek Kroemeke discovered that the mod_proxy module incorrectly handled
certain requests. A remote attacker could use this issue to cause the
server to stop responding, leading to a denial of service. This issue only
affected Ubuntu 14.04 LTS. (CVE-2014-0117)

Giancarlo Pellegrino and Davide Balzarotti discovered that the mod_deflate
module incorrectly handled body decompression. A remote attacker could use
this issue to cause resource consumption, leading to a denial of service.
(CVE-2014-0118)

Marek Kroemeke and others discovered that the mod_status module incorrectly
handled certain requests. A remote attacker could use this issue to cause
the server to stop responding, leading to a denial of service, or possibly
execute arbitrary code. (CVE-2014-0226)

Rainer Jung discovered that the mod_cgid module incorrectly handled certain
scripts. A remote attacker could use this issue to cause the server to stop
responding, leading to a denial of service. (CVE-2014-0231)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
