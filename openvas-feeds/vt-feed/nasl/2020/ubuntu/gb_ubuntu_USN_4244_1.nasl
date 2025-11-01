# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844301");
  script_cve_id("CVE-2019-14902", "CVE-2019-14907", "CVE-2019-19344");
  script_tag(name:"creation_date", value:"2020-01-22 04:00:35 +0000 (Wed, 22 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-29 13:15:00 +0000 (Sat, 29 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-4244-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4244-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4244-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-4244-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Samba did not automatically replicate ACLs set to
inherit down a subtree on AD Directory, contrary to expectations. This
issue was only addressed in Ubuntu 18.04 LTS, Ubuntu 19.04 and Ubuntu
19.10. (CVE-2019-14902)

Robert Swiecki discovered that Samba incorrectly handled certain character
conversions when the log level is set to 3 or above. In certain
environments, a remote attacker could possibly use this issue to cause
Samba to crash, resulting in a denial of service. (CVE-2019-14907)

Christian Naumer discovered that Samba incorrectly handled DNS zone
scavenging. This issue could possibly result in some incorrect data being
written to the DB. This issue only applied to Ubuntu 19.04 and Ubuntu
19.10. (CVE-2019-19344)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
