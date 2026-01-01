# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.910123397410122");
  script_cve_id("CVE-2025-6176", "CVE-2025-66471");
  script_tag(name:"creation_date", value:"2025-12-18 04:17:43 +0000 (Thu, 18 Dec 2025)");
  script_version("2025-12-18T05:46:55+0000");
  script_tag(name:"last_modification", value:"2025-12-18 05:46:55 +0000 (Thu, 18 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-10 16:10:33 +0000 (Wed, 10 Dec 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-9e233a4e22)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-9e233a4e22");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-9e233a4e22");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2419491");
  script_xref(name:"URL", value:"https://github.com/google/brotli/blob/v1.2.0/CHANGELOG.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'brotli, perl-Alien-Brotli' package(s) announced via the FEDORA-2025-9e233a4e22 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update `brotli` to [1.2.0]([link moved to references]).

This update provides the necessary Python APIs in `python3-brotli` to fix denial-of-service security issues related to 'decompression bombs,' such as CVE-2025-66471 or CVE-2025-6176, but actually fixing them would require separate updates in affected packages.");

  script_tag(name:"affected", value:"'brotli, perl-Alien-Brotli' package(s) on Fedora 42.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"brotli", rpm:"brotli~1.2.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brotli-debuginfo", rpm:"brotli-debuginfo~1.2.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brotli-debugsource", rpm:"brotli-debugsource~1.2.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brotli-devel", rpm:"brotli-devel~1.2.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbrotli", rpm:"libbrotli~1.2.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbrotli-debuginfo", rpm:"libbrotli-debuginfo~1.2.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Alien-Brotli", rpm:"perl-Alien-Brotli~0.2.2~11.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Alien-Brotli-tests", rpm:"perl-Alien-Brotli-tests~0.2.2~11.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-brotli", rpm:"python3-brotli~1.2.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-brotli-debuginfo", rpm:"python3-brotli-debuginfo~1.2.0~1.fc42", rls:"FC42"))) {
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
