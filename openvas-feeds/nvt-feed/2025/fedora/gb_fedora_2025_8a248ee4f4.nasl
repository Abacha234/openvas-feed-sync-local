# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.89724810110141024");
  script_cve_id("CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61725");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-8a248ee4f4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-8a248ee4f4");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-8a248ee4f4");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407848");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408084");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408629");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408684");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409315");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409554");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah, podman' package(s) announced via the FEDORA-2025-8a248ee4f4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for podman-5.7.0-1.fc42, buildah-1.42.1-1.fc42.

##### **Changelog for podman**

```
* Tue Nov 11 2025 Packit <hello@packit.dev> - 5:5.7.0-1
- Update to 5.7.0 upstream release

* Thu Oct 30 2025 Packit <hello@packit.dev> - 5:5.7.0~rc2-1
- Update to 5.7.0-rc2 upstream release

* Tue Oct 28 2025 Lokesh Mandvekar <lsm5@redhat.com> - 5:5.7.0~rc1-1
- bump to v5.7.0-rc1

```

##### **Changelog for buildah**

```
* Tue Nov 11 2025 Packit <hello@packit.dev> - 2:1.42.1-1
- Update to 1.42.1 upstream release

* Mon Nov 03 2025 Lokesh Mandvekar <lsm5@redhat.com> - 2:1.42.0-3
- Rebuild for CVE fixes

* Thu Oct 23 2025 Lokesh Mandvekar <lsm5@redhat.com> - 2:1.42.0-2
- cleanup changelog

* Wed Oct 22 2025 Packit <hello@packit.dev> - 2:1.42.0-1
- Update to 1.42.0 upstream release

```");

  script_tag(name:"affected", value:"'buildah, podman' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.42.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-debuginfo", rpm:"buildah-debuginfo~1.42.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-debugsource", rpm:"buildah-debugsource~1.42.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-tests", rpm:"buildah-tests~1.42.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-tests-debuginfo", rpm:"buildah-tests-debuginfo~1.42.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~5.7.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debuginfo", rpm:"podman-debuginfo~5.7.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debugsource", rpm:"podman-debugsource~5.7.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~5.7.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-machine", rpm:"podman-machine~5.7.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~5.7.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote-debuginfo", rpm:"podman-remote-debuginfo~5.7.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-tests", rpm:"podman-tests~5.7.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-tests-debuginfo", rpm:"podman-tests-debuginfo~5.7.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podmansh", rpm:"podmansh~5.7.0~1.fc42", rls:"FC42"))) {
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
