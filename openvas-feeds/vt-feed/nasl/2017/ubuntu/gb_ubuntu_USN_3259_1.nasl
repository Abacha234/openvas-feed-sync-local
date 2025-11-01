# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843133");
  script_cve_id("CVE-2017-3136", "CVE-2017-3137", "CVE-2017-3138");
  script_tag(name:"creation_date", value:"2017-04-21 04:44:43 +0000 (Fri, 21 Apr 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3259-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3259-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3259-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-3259-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the resolver in Bind made incorrect
assumptions about ordering when processing responses containing
a CNAME or DNAME. An attacker could use this cause a denial of
service. (CVE-2017-3137)

Oleg Gorokhov discovered that in some situations, Bind did not properly
handle DNS64 queries. An attacker could use this to cause a denial
of service. (CVE-2017-3136)

Mike Lalumiere discovered that in some situations, Bind did
not properly handle invalid operations requested via its control
channel. An attacker with access to the control channel could cause
a denial of service. (CVE-2017-3138)");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
