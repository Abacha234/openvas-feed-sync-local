# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841399");
  script_cve_id("CVE-2012-2942", "CVE-2013-1912");
  script_tag(name:"creation_date", value:"2013-04-19 04:38:56 +0000 (Fri, 19 Apr 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1800-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1800-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1800-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy' package(s) announced via the USN-1800-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that HAProxy incorrectly handled configurations where
global.tune.bufsize was set to a value higher than the default. A remote
attacker could use this issue to cause a denial of service, or possibly
execute arbitrary code. (CVE-2012-2942)

Yves Lafon discovered that HAProxy incorrectly handled HTTP keywords in TCP
inspection rules when HTTP keep-alive is enabled. A remote attacker could
use this issue to cause a denial of service, or possibly execute arbitrary
code. (CVE-2013-1912)");

  script_tag(name:"affected", value:"'haproxy' package(s) on Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
