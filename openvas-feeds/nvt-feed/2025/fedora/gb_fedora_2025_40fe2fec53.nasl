# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.4010210121021019953");
  script_cve_id("CVE-2025-14104");
  script_tag(name:"creation_date", value:"2025-12-17 10:50:36 +0000 (Wed, 17 Dec 2025)");
  script_version("2025-12-18T05:46:55+0000");
  script_tag(name:"last_modification", value:"2025-12-18 05:46:55 +0000 (Thu, 18 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-05 17:16:03 +0000 (Fri, 05 Dec 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-40fe2fec53)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-40fe2fec53");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-40fe2fec53");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'util-linux' package(s) announced via the FEDORA-2025-40fe2fec53 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"upstream stable upgrade from 2.41.1 to 2.41.3 (CVE-2025-14104 and other issues)");

  script_tag(name:"affected", value:"'util-linux' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"libblkid", rpm:"libblkid~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid-debuginfo", rpm:"libblkid-debuginfo~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid-devel", rpm:"libblkid-devel~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk", rpm:"libfdisk~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk-debuginfo", rpm:"libfdisk-debuginfo~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk-devel", rpm:"libfdisk-devel~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblastlog2", rpm:"liblastlog2~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblastlog2-debuginfo", rpm:"liblastlog2-debuginfo~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblastlog2-devel", rpm:"liblastlog2-devel~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount", rpm:"libmount~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount-debuginfo", rpm:"libmount-debuginfo~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount-devel", rpm:"libmount-devel~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols", rpm:"libsmartcols~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols-debuginfo", rpm:"libsmartcols-debuginfo~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols-devel", rpm:"libsmartcols-devel~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid", rpm:"libuuid~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid-debuginfo", rpm:"libuuid-debuginfo~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid-devel", rpm:"libuuid-devel~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libmount", rpm:"python3-libmount~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libmount-debuginfo", rpm:"python3-libmount-debuginfo~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux", rpm:"util-linux~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-core", rpm:"util-linux-core~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-core-debuginfo", rpm:"util-linux-core-debuginfo~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-debuginfo", rpm:"util-linux-debuginfo~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-debugsource", rpm:"util-linux-debugsource~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-i18n", rpm:"util-linux-i18n~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-script", rpm:"util-linux-script~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-script-debuginfo", rpm:"util-linux-script-debuginfo~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uuidd", rpm:"uuidd~2.41.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uuidd-debuginfo", rpm:"uuidd-debuginfo~2.41.3~7.fc43", rls:"FC43"))) {
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
