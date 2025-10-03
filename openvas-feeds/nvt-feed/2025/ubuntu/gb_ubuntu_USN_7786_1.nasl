# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7786.1");
  script_cve_id("CVE-2025-9230", "CVE-2025-9231", "CVE-2025-9232");
  script_tag(name:"creation_date", value:"2025-10-02 04:04:33 +0000 (Thu, 02 Oct 2025)");
  script_version("2025-10-02T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-10-02 05:38:29 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7786-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7786-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7786-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl, openssl1.0' package(s) announced via the USN-7786-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stanislav Fort discovered that OpenSSL incorrectly handled memory when
trying to decrypt CMS messages encrypted with password-based encryption. An
attacker could possibly use this issue to cause a denial of service or
execute arbitrary code. (CVE-2025-9230)

Stanislav Fort discovered that OpenSSL had a timing side-channel in SM2
signature computations on ARM platforms. A remote attacker could possibly
use this issue to recover private data. This issue only affected Ubuntu
25.04. (CVE-2025-9231)

Stanislav Fort discovered that OpenSSL incorrectly handled memory during
HTTP requests when 'no_proxy' environment variable is set. An attacker
could possibly use this issue to cause a denial of service. This issue only
affected Ubuntu 25.04. (CVE-2025-9232)");

  script_tag(name:"affected", value:"'openssl, openssl1.0' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu2.27+esm11", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.1f-1ubuntu2.27+esm11", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2g-1ubuntu4.20+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.2g-1ubuntu4.20+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2n-1ubuntu5.13+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1-1ubuntu2.1~18.04.23+esm6", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.1.1-1ubuntu2.1~18.04.23+esm6", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl1.0", ver:"1.0.2n-1ubuntu5.13+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1f-1ubuntu2.24+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.1.1f-1ubuntu2.24+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.2-0ubuntu1.20", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"3.0.2-0ubuntu1.20", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl3t64", ver:"3.0.13-0ubuntu3.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"3.0.13-0ubuntu3.6", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl3t64", ver:"3.4.1-1ubuntu4", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"3.4.1-1ubuntu4", rls:"UBUNTU25.04"))) {
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
