# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843336");
  script_cve_id("CVE-2015-5223", "CVE-2016-0737", "CVE-2016-0738");
  script_tag(name:"creation_date", value:"2017-10-12 08:27:08 +0000 (Thu, 12 Oct 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-06 03:05:00 +0000 (Tue, 06 Dec 2016)");

  script_name("Ubuntu: Security Advisory (USN-3451-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3451-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3451-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'swift' package(s) announced via the USN-3451-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenStack Swift incorrectly handled tempurls. A
remote authenticated user in possession of a tempurl key authorized for PUT
could retrieve other objects in the same Swift account. (CVE-2015-5223)

Romain Le Disez and Orjan Persson discovered that OpenStack Swift
incorrectly closed client connections. A remote attacker could possibly use
this issue to consume resources, resulting in a denial of service.
(CVE-2016-0737, CVE-2016-0738)");

  script_tag(name:"affected", value:"'swift' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
