# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7851.1");
  script_cve_id("CVE-2025-31133", "CVE-2025-52565", "CVE-2025-52881");
  script_tag(name:"creation_date", value:"2025-11-06 14:11:25 +0000 (Thu, 06 Nov 2025)");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7851-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7851-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7851-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'runc-app, runc-stable' package(s) announced via the USN-7851-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lei Wang and Li Fubang discovered that runC incorrectly handled masked
paths. An attacker could possibly replace a container's /dev/null
with a symlink to some other procfs file and possibly escape a container.
(CVE-2025-31133)

Lei Wang and Li Fubang discovered that runC incorrectly handled the
/dev/console bind-mounts. An attacker could potentially exploit this issue
to build-mount a symlink and escape a container. (CVE-2025-52565)

Li Fubang and Tonis Tiigi discovered that the fix for CVE-2019-16884 was
incomplete. An attacker could possibly use this issue to cause a denial of
service or escape the container. (CVE-2025-52881)");

  script_tag(name:"affected", value:"'runc-app, runc-stable' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"runc", ver:"1.3.3-0ubuntu1~22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"runc", ver:"1.3.3-0ubuntu1~24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"runc", ver:"1.3.3-0ubuntu1~25.04.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"runc", ver:"1.3.3-0ubuntu1~25.10.2", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"runc-stable", ver:"1.3.3-0ubuntu1~25.10.2", rls:"UBUNTU25.10"))) {
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
