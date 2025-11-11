# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0270");
  script_cve_id("CVE-2024-28956", "CVE-2024-31143", "CVE-2024-31144", "CVE-2024-31145", "CVE-2024-31146", "CVE-2024-36350", "CVE-2024-36357", "CVE-2024-45817", "CVE-2024-45818", "CVE-2024-45819", "CVE-2024-53240", "CVE-2024-53241", "CVE-2025-1713", "CVE-2025-27462", "CVE-2025-27463", "CVE-2025-27464", "CVE-2025-27465");
  script_tag(name:"creation_date", value:"2025-11-10 04:13:47 +0000 (Mon, 10 Nov 2025)");
  script_version("2025-11-10T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-11-10 05:40:50 +0000 (Mon, 10 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-08 14:50:58 +0000 (Wed, 08 Oct 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0270)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0270");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0270.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33401");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/KEACKX57LEHS2YKZ4PO5DYNOQRGQSDO2/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/16/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/16/4");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/08/14/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/08/14/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/09/24/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/11/12/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/11/12/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/12/17/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/12/17/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/02/27/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/05/12/4");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/05/12/5");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/05/27/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/01/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/08/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/08/28/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/09/09/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/09/09/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/09/09/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/10/21/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/10/24/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/11/05/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the MGASA-2025-0270 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Double unlock in x86 guest IRQ handling. (CVE-2024-31143)
Xapi: Metadata injection attack against backup/restore functionality.
(CVE-2024-31144)
Error handling in x86 IOMMU identity mapping. (CVE-2024-31145)
PCI device pass-through with shared resources. (CVE-2024-31146)
x86: Deadlock in vlapic_error(). (CVE-2024-45817)
Deadlock in x86 HVM standard VGA handling. (CVE-2024-45818)
libxl leaks data to PVH guests via ACPI tables. (CVE-2024-45819)
Backend can crash Linux netfront. (CVE-2024-53240)
Xen hypercall page unsafe against speculative attacks. (CVE-2024-53241)
Deadlock potential with VT-d and legacy PCI device pass-through.
(CVE-2025-1713)
x86: Indirect Target Selection. (CVE-2024-28956)
x86: Incorrect stubs exception handling for flags recovery.
(CVE-2025-27465)
TSA-SQ (TSA in the Store Queues). (CVE-2024-36350)
TSA-L1 (TSA in the L1 data cache). (CVE-2024-36357)
A NULL pointer dereference in the updating of the reference TSC area.
(CVE-2025-27466)
A NULL pointer dereference by assuming the SIM page is mapped when a
synthetic timer message has to be delivered. (CVE-2025-58142)
A race in the mapping of the reference TSC page, where a guest can get
Xen to free a page while still present in the guest physical to machine
(p2m) page tables. (CVE-2025-58143)
An assertion is wrong there, where the case actually needs handling. A
NULL pointer de-reference could result on a release build.
(CVE-2025-58144)
The P2M lock isn't held until a page reference was actually obtained (or
the attempt to do so has failed). Otherwise the page can not only
change type, but even ownership in between, thus allowing domain
boundaries to be violated. (CVE-2025-58145)
XAPI UTF-8 string handling. (CVE-2025-58146)
Hypercalls using the HV_VP_SET Sparse format can cause vpmask_set() to
write out of bounds when converting the bitmap to Xen's format.
(CVE-2025-58147)
Hypercalls using any input format can cause send_ipi() to read d->vcpu[]
out-of-bounds, and operate on a wild vCPU pointer.(CVE-2025-58148)
Incorrect removal of permissions on PCI device unplug. (CVE-2025-58149)");

  script_tag(name:"affected", value:"'xen' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64xen-devel", rpm:"lib64xen-devel~4.17.5~1.git20251028.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xen3.0", rpm:"lib64xen3.0~4.17.5~1.git20251028.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxen-devel", rpm:"libxen-devel~4.17.5~1.git20251028.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxen3.0", rpm:"libxen3.0~4.17.5~1.git20251028.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-xen", rpm:"ocaml-xen~4.17.5~1.git20251028.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-xen-devel", rpm:"ocaml-xen-devel~4.17.5~1.git20251028.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.17.5~1.git20251028.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-hypervisor", rpm:"xen-hypervisor~4.17.5~1.git20251028.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-licenses", rpm:"xen-licenses~4.17.5~1.git20251028.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-runtime", rpm:"xen-runtime~4.17.5~1.git20251028.1.mga9", rls:"MAGEIA9"))) {
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
