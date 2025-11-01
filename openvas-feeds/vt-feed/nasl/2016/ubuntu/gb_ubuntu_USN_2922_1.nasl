# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842679");
  script_cve_id("CVE-2013-0213", "CVE-2013-0214", "CVE-2015-7560", "CVE-2016-0771");
  script_tag(name:"creation_date", value:"2016-03-10 05:16:57 +0000 (Thu, 10 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:25:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-2922-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2922-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2922-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-2922-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeremy Allison discovered that Samba incorrectly handled ACLs on symlink
paths. A remote attacker could use this issue to overwrite the ownership of
ACLs using symlinks. (CVE-2015-7560)

Garming Sam and Douglas Bagnall discovered that the Samba internal DNS
server incorrectly handled certain DNS TXT records. A remote attacker could
use this issue to cause Samba to crash, resulting in a denial of service,
or possibly obtain uninitialized memory contents. This issue only applied
to Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2016-0771)

It was discovered that the Samba Web Administration Tool (SWAT) was
vulnerable to clickjacking and cross-site request forgery attacks. This
issue only affected Ubuntu 12.04 LTS. (CVE-2013-0213, CVE-2013-0214)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
