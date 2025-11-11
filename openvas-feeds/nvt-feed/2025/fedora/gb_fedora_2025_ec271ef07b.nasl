# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.101992711011020798");
  script_cve_id("CVE-2025-58147", "CVE-2025-58148", "CVE-2025-58149");
  script_tag(name:"creation_date", value:"2025-11-10 04:10:19 +0000 (Mon, 10 Nov 2025)");
  script_version("2025-11-10T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-11-10 05:40:50 +0000 (Mon, 10 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-ec271ef07b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-ec271ef07b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-ec271ef07b");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the FEDORA-2025-ec271ef07b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Incorrect removal of permissions on PCI device unplug [XSA-476,
CVE-2025-58149]

----

x86: Incorrect input sanitisation in Viridian hypercalls [XSA-475,
CVE-2025-58147, CVE-2025-58148]");

  script_tag(name:"affected", value:"'xen' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debuginfo", rpm:"xen-debuginfo~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc", rpm:"xen-doc~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-hypervisor", rpm:"xen-hypervisor~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-licenses", rpm:"xen-licenses~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-ocaml", rpm:"xen-ocaml~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-ocaml-debuginfo", rpm:"xen-ocaml-debuginfo~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-ocaml-devel", rpm:"xen-ocaml-devel~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-runtime", rpm:"xen-runtime~4.19.3~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-runtime-debuginfo", rpm:"xen-runtime-debuginfo~4.19.3~8.fc42", rls:"FC42"))) {
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
