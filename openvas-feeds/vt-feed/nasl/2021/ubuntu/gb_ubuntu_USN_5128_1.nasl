# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845119");
  script_cve_id("CVE-2020-27781", "CVE-2021-20288", "CVE-2021-3509", "CVE-2021-3524", "CVE-2021-3531");
  script_tag(name:"creation_date", value:"2021-11-02 02:01:00 +0000 (Tue, 02 Nov 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-03 18:28:00 +0000 (Thu, 03 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-5128-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5128-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5128-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the USN-5128-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Goutham Pacha Ravi, Jahson Babel, and John Garbutt discovered that user
credentials in Ceph could be manipulated in certain environments. An
attacker could use this to gain unintended access to resources. This issue
only affected Ubuntu 18.04 LTS. (CVE-2020-27781)

It was discovered that Ceph contained an authentication flaw, leading to
key reuse. An attacker could use this to cause a denial of service or
possibly impersonate another user. This issue only affected Ubuntu 21.04.
(CVE-2021-20288)

Sergey Bobrov discovered that the Ceph dashboard was susceptible to a
cross-site scripting attack. An attacker could use this to expose sensitive
information or gain unintended access. This issue only affected Ubuntu
21.04. (CVE-2021-3509)

Sergey Bobrov discovered that Ceph's RadosGW (Ceph Object Gateway) allowed
the injection of HTTP headers in responses to CORS requests. An attacker
could use this to violate system integrity. (CVE-2021-3524)

It was discovered that Ceph's RadosGW (Ceph Object Gateway) did not
properly handle GET requests for swift URLs in some situations, leading to
an application crash. An attacker could use this to cause a denial of
service. (CVE-2021-3531)");

  script_tag(name:"affected", value:"'ceph' package(s) on Ubuntu 18.04, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
