# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7824.2");
  script_cve_id("CVE-2025-49844");
  script_tag(name:"creation_date", value:"2025-10-17 04:05:08 +0000 (Fri, 17 Oct 2025)");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-07 15:40:02 +0000 (Tue, 07 Oct 2025)");

  script_name("Ubuntu: Security Advisory (USN-7824-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(25\.04|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7824-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7824-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redict' package(s) announced via the USN-7824-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7824-1 fixed several vulnerabilities in Redis. This update provides
the corresponding update for Redict - a fork of Redis.

Original advisory details:

Benny Isaacs, Nir Brakha, and Sagi Tzadik discovered that Redis incorrectly
handled memory when running Lua scripts. An authenticated attacker could use
this vulnerability to trigger a use-after-free condition, and potentially
achieve remote code execution on the Redis server.");

  script_tag(name:"affected", value:"'redict' package(s) on Ubuntu 25.04, Ubuntu 25.10.");

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

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"redict", ver:"7.3.2+ds-1ubuntu0.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redict-sentinel", ver:"7.3.2+ds-1ubuntu0.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redict-server", ver:"7.3.2+ds-1ubuntu0.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redict-tools", ver:"7.3.2+ds-1ubuntu0.1", rls:"UBUNTU25.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"redict", ver:"7.3.5+ds-1ubuntu0.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redict-sentinel", ver:"7.3.5+ds-1ubuntu0.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redict-server", ver:"7.3.5+ds-1ubuntu0.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redict-tools", ver:"7.3.5+ds-1ubuntu0.1", rls:"UBUNTU25.10"))) {
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
