# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2532");
  script_cve_id("CVE-2025-10230", "CVE-2025-9640");
  script_tag(name:"creation_date", value:"2025-12-11 12:41:26 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-12T05:45:42+0000");
  script_tag(name:"last_modification", value:"2025-12-12 05:45:42 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-07 20:15:35 +0000 (Fri, 07 Nov 2025)");

  script_name("Huawei EulerOS: Security Advisory for samba (EulerOS-SA-2025-2532)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2532");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2532");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'samba' package(s) announced via the EulerOS-SA-2025-2532 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been found in Samba (File Transfer Software) (the affected version is unknown) and classified as critical.The CWE definition for the vulnerability is CWE-77. The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.As an impact it is known to affect confidentiality, integrity, and availability.There is no information about possible countermeasures known. It may be suggested to replace the affected object with an alternative product.(CVE-2025-10230)

A flaw was found in Samba, in the vfs_streams_xattr module, where uninitialized heap memory could be written into alternate data streams. This allows an authenticated user to read residual memory content that may include sensitive data, resulting in an information disclosure vulnerability.(CVE-2025-9640)");

  script_tag(name:"affected", value:"'samba' package(s) on Huawei EulerOS V2.0SP13.");

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

if(release == "EULEROS-2.0SP13") {

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~4.17.5~9.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient", rpm:"libwbclient~4.17.5~9.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.17.5~9.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.17.5~9.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.17.5~9.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~4.17.5~9.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common-tools", rpm:"samba-common-tools~4.17.5~9.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.17.5~9.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.17.5~9.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~4.17.5~9.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-modules", rpm:"samba-winbind-modules~4.17.5~9.h2.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
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
