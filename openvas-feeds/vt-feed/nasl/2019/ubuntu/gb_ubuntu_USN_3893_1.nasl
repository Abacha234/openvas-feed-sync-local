# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843913");
  script_cve_id("CVE-2018-5744", "CVE-2018-5745", "CVE-2019-6465");
  script_tag(name:"creation_date", value:"2019-02-23 03:07:11 +0000 (Sat, 23 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-05 16:58:00 +0000 (Tue, 05 Nov 2019)");

  script_name("Ubuntu: Security Advisory (USN-3893-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3893-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3893-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-3893-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Toshifumi Sakaguchi discovered that Bind incorrectly handled memory. A
remote attacker could possibly use this issue to cause Bind to consume
resources, leading to a denial of service. This issue only affected Ubuntu
18.04 LTS and Ubuntu 18.10. (CVE-2018-5744)

It was discovered that Bind incorrectly handled certain trust anchors when
used with the 'managed-keys' feature. A remote attacker could possibly use
this issue to cause Bind to crash, resulting in a denial of service.
(CVE-2018-5745)

It was discovered that Bind incorrectly handled certain controls for zone
transfers, contrary to expectations. (CVE-2019-6465)");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
