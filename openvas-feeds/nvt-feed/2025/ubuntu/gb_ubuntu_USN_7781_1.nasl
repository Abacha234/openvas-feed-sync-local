# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7781.1");
  script_cve_id("CVE-2019-0053", "CVE-2020-10188", "CVE-2022-39028", "CVE-2023-40303");
  script_tag(name:"creation_date", value:"2025-09-30 04:04:44 +0000 (Tue, 30 Sep 2025)");
  script_version("2025-09-30T05:39:19+0000");
  script_tag(name:"last_modification", value:"2025-09-30 05:39:19 +0000 (Tue, 30 Sep 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-06 19:22:03 +0000 (Fri, 06 Mar 2020)");

  script_name("Ubuntu: Security Advisory (USN-7781-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7781-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7781-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'inetutils' package(s) announced via the USN-7781-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matthew Hickey discovered that Inetutils did not correctly handle certain
escape characters. An attacker could possibly use this issue to cause a
denial of service. (CVE-2019-0053)

It was discovered that Inetutils did not correctly handle certain memory
operations. An attacker could possibly use this issue to execute arbitrary
code. This issue only affected Ubuntu 14.04 LTS. (CVE-2020-10188)

It was discovered that Inetutils did not correctly handle certain memory
operations. An attacker could possibly use this issue to cause a denial of
service. (CVE-2022-39028)

It was discovered that Inetutils did not check the return values of set*id
functions. An attacker could possibly use this issue to escalate their
privileges. (CVE-2023-40303)");

  script_tag(name:"affected", value:"'inetutils' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ftp", ver:"2:1.9.2-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ftpd", ver:"2:1.9.2-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-inetd", ver:"2:1.9.2-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ping", ver:"2:1.9.2-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-syslogd", ver:"2:1.9.2-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-talk", ver:"2:1.9.2-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-telnet", ver:"2:1.9.2-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-tools", ver:"2:1.9.2-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-traceroute", ver:"2:1.9.2-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ftp", ver:"2:1.9.4-1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ftpd", ver:"2:1.9.4-1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-inetd", ver:"2:1.9.4-1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ping", ver:"2:1.9.4-1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-syslogd", ver:"2:1.9.4-1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-talk", ver:"2:1.9.4-1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-telnet", ver:"2:1.9.4-1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-tools", ver:"2:1.9.4-1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-traceroute", ver:"2:1.9.4-1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ftp", ver:"2:1.9.4-3ubuntu0.1+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ftpd", ver:"2:1.9.4-3ubuntu0.1+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-inetd", ver:"2:1.9.4-3ubuntu0.1+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ping", ver:"2:1.9.4-3ubuntu0.1+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-syslogd", ver:"2:1.9.4-3ubuntu0.1+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-talk", ver:"2:1.9.4-3ubuntu0.1+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-telnet", ver:"2:1.9.4-3ubuntu0.1+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-tools", ver:"2:1.9.4-3ubuntu0.1+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-traceroute", ver:"2:1.9.4-3ubuntu0.1+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ftp", ver:"2:1.9.4-11ubuntu0.2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ftpd", ver:"2:1.9.4-11ubuntu0.2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-inetd", ver:"2:1.9.4-11ubuntu0.2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-ping", ver:"2:1.9.4-11ubuntu0.2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-syslogd", ver:"2:1.9.4-11ubuntu0.2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-talk", ver:"2:1.9.4-11ubuntu0.2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-telnet", ver:"2:1.9.4-11ubuntu0.2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-tools", ver:"2:1.9.4-11ubuntu0.2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inetutils-traceroute", ver:"2:1.9.4-11ubuntu0.2+esm1", rls:"UBUNTU20.04 LTS"))) {
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
