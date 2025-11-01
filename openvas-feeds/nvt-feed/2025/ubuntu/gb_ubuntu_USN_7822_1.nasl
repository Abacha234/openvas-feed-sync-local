# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7822.1");
  script_cve_id("CVE-2025-55247", "CVE-2025-55248", "CVE-2025-55315");
  script_tag(name:"creation_date", value:"2025-10-20 04:08:38 +0000 (Mon, 20 Oct 2025)");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-14 17:15:44 +0000 (Tue, 14 Oct 2025)");

  script_name("Ubuntu: Security Advisory (USN-7822-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7822-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7822-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dotnet8, dotnet9, dotnet10' package(s) announced via the USN-7822-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that .NET did not properly handle the creation of temporary
build time directories. An attacker could possibly use this issue to cause a
denial of service. (CVE-2025-55247)

It was discovered that .NET did not properly establish TLS sessions for
SMTP server connections. An attacker could use this issue to cause .NET
to use unencrypted connections. This issue only affects .NET versions 8.0
and 9.0. (CVE-2025-55248)

It was discovered that .NET inconsistently interpreted certain http
requests. An attacker could possibly use this to bypass a security feature
over a network. (CVE-2025-55315)");

  script_tag(name:"affected", value:"'dotnet8, dotnet9, dotnet10' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-8.0", ver:"8.0.21-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-8.0", ver:"8.0.21-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-8.0", ver:"8.0.21-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-8.0", ver:"8.0.21-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-8.0", ver:"8.0.121-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet8", ver:"8.0.121-8.0.21-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-8.0", ver:"8.0.21-0ubuntu1~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-8.0", ver:"8.0.21-0ubuntu1~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-8.0", ver:"8.0.21-0ubuntu1~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-8.0", ver:"8.0.21-0ubuntu1~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-8.0", ver:"8.0.121-0ubuntu1~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet8", ver:"8.0.121-8.0.21-0ubuntu1~24.04.1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-8.0", ver:"8.0.21-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-9.0", ver:"9.0.10-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-8.0", ver:"8.0.21-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-9.0", ver:"9.0.10-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-8.0", ver:"8.0.21-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-9.0", ver:"9.0.10-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-8.0", ver:"8.0.21-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-9.0", ver:"9.0.10-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-8.0", ver:"8.0.121-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-9.0", ver:"9.0.111-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-aot-9.0", ver:"9.0.111-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet8", ver:"8.0.121-8.0.21-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet9", ver:"9.0.111-9.0.10-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-10.0", ver:"10.0.0~rc2-0ubuntu1~25.10.2", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-8.0", ver:"8.0.21-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-9.0", ver:"9.0.10-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-10.0", ver:"10.0.0~rc2-0ubuntu1~25.10.2", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-8.0", ver:"8.0.21-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-9.0", ver:"9.0.10-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-10.0", ver:"10.0.0~rc2-0ubuntu1~25.10.2", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-8.0", ver:"8.0.21-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-9.0", ver:"9.0.10-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-10.0", ver:"10.0.0~rc2-0ubuntu1~25.10.2", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-8.0", ver:"8.0.21-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-9.0", ver:"9.0.10-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-10.0", ver:"10.0.100~rc2-0ubuntu1~25.10.2", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-8.0", ver:"8.0.121-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-9.0", ver:"9.0.111-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-aot-10.0", ver:"10.0.100~rc2-0ubuntu1~25.10.2", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-aot-9.0", ver:"9.0.111-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet10", ver:"10.0.100-10.0.0~rc2-0ubuntu1~25.10.2", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet8", ver:"8.0.121-8.0.21-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet9", ver:"9.0.111-9.0.10-0ubuntu1~25.10.1", rls:"UBUNTU25.10"))) {
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
