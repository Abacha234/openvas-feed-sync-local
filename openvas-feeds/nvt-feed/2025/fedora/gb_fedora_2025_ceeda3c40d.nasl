# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.991011011009739940100");
  script_cve_id("CVE-2025-9615");
  script_tag(name:"creation_date", value:"2025-12-18 04:17:43 +0000 (Thu, 18 Dec 2025)");
  script_version("2025-12-18T05:46:55+0000");
  script_tag(name:"last_modification", value:"2025-12-18 05:46:55 +0000 (Thu, 18 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-ceeda3c40d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-ceeda3c40d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-ceeda3c40d");
  script_xref(name:"URL", value:"https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/merge_requests/2325");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'NetworkManager' package(s) announced via the FEDORA-2025-ceeda3c40d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.54.3 Partially fixes CVE-2025-9615. To protect totally from it, see: [link moved to references].

----

Update to 1.54.3
Partially fixes CVE-2025-9615. To protect totally from it, see:
[link moved to references].");

  script_tag(name:"affected", value:"'NetworkManager' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-adsl", rpm:"NetworkManager-adsl~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-adsl-debuginfo", rpm:"NetworkManager-adsl-debuginfo~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-bluetooth", rpm:"NetworkManager-bluetooth~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-bluetooth-debuginfo", rpm:"NetworkManager-bluetooth-debuginfo~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-cloud-setup", rpm:"NetworkManager-cloud-setup~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-cloud-setup-debuginfo", rpm:"NetworkManager-cloud-setup-debuginfo~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-config-connectivity-fedora", rpm:"NetworkManager-config-connectivity-fedora~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-config-server", rpm:"NetworkManager-config-server~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-debuginfo", rpm:"NetworkManager-debuginfo~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-debugsource", rpm:"NetworkManager-debugsource~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-libnm", rpm:"NetworkManager-libnm~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-libnm-debuginfo", rpm:"NetworkManager-libnm-debuginfo~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-libnm-devel", rpm:"NetworkManager-libnm-devel~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-ovs", rpm:"NetworkManager-ovs~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-ovs-debuginfo", rpm:"NetworkManager-ovs-debuginfo~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-ppp", rpm:"NetworkManager-ppp~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-ppp-debuginfo", rpm:"NetworkManager-ppp-debuginfo~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-team", rpm:"NetworkManager-team~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-team-debuginfo", rpm:"NetworkManager-team-debuginfo~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-tui", rpm:"NetworkManager-tui~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-tui-debuginfo", rpm:"NetworkManager-tui-debuginfo~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-wifi", rpm:"NetworkManager-wifi~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-wifi-debuginfo", rpm:"NetworkManager-wifi-debuginfo~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-wwan", rpm:"NetworkManager-wwan~1.54.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-wwan-debuginfo", rpm:"NetworkManager-wwan-debuginfo~1.54.3~2.fc43", rls:"FC43"))) {
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
