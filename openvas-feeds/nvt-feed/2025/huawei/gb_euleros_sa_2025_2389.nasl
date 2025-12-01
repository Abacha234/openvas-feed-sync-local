# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2389");
  script_cve_id("CVE-2025-47268", "CVE-2025-48964");
  script_tag(name:"creation_date", value:"2025-11-12 04:29:57 +0000 (Wed, 12 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for iputils (EulerOS-SA-2025-2389)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2389");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2389");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'iputils' package(s) announced via the EulerOS-SA-2025-2389 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ping in iputils before 20250602 allows a denial of service (application error or incorrect data collection) via a crafted ICMP Echo Reply packet, because of a signed 64-bit integer overflow in timestamp multiplication.(CVE-2025-47268)

ping in iputils before 20250602 allows a denial of service (application error in adaptive ping mode or incorrect data collection) via a crafted ICMP Echo Reply packet, because a zero timestamp can lead to large intermediate values that have an integer overflow when squared during statistics calculations. NOTE: this issue exists because of an incomplete fix for CVE-2025-47268 (that fix was only about timestamp calculations, and it did not account for a specific scenario where the original timestamp in the ICMP payload is zero).(CVE-2025-48964)");

  script_tag(name:"affected", value:"'iputils' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

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

if(release == "EULEROS-2.0SP10-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"iputils", rpm:"iputils~20190709~6.h8.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
