# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7926.1");
  script_cve_id("CVE-2021-3563", "CVE-2022-2447", "CVE-2025-65073");
  script_tag(name:"creation_date", value:"2025-12-12 08:49:02 +0000 (Fri, 12 Dec 2025)");
  script_version("2025-12-12T15:41:28+0000");
  script_tag(name:"last_modification", value:"2025-12-12 15:41:28 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 17:24:32 +0000 (Mon, 28 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-7926-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7926-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7926-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keystone' package(s) announced via the USN-7926-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kay discovered that OpenStack Keystone incorrectly handled the ec2tokens
and s3tokens APIs. A remote attacker could possibly use this issue to
obtain unauthorized access and escalate privileges. (CVE-2025-65073)

It was discovered that OpenStack Keystone only validated the first 72
bytes of an application secret. An attacker could possibly use this issue
to bypass password complexity. (CVE-2021-3563)

It was discovered that OpenStack Keystone had a time lag before a token
should be revoked by the security policy. A remote administrator could use
this issue to maintain access for longer than expected. (CVE-2022-2447)");

  script_tag(name:"affected", value:"'keystone' package(s) on Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"keystone", ver:"2:21.0.1-0ubuntu2.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-keystone", ver:"2:21.0.1-0ubuntu2.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
