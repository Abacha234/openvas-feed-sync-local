# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2571");
  script_cve_id("CVE-2024-38797", "CVE-2025-3770");
  script_tag(name:"creation_date", value:"2025-12-19 04:38:02 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T05:45:49+0000");
  script_tag(name:"last_modification", value:"2025-12-19 05:45:49 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for EDK2 (EulerOS-SA-2025-2571)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.13\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2571");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2571");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'EDK2' package(s) announced via the EulerOS-SA-2025-2571 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"EDK2 contains a vulnerability in BIOS where an attacker may cause 'Protection Mechanism Failure' by local access. Successful exploitation of this vulnerability will lead to arbitrary code execution and impact Confidentiality, Integrity, and Availability.(CVE-2025-3770)

EDK2 contains a vulnerability in the HashPeImageByType(). A user may cause a read out of bounds when a corrupted data pointer and length are sent via an adjecent network. A successful exploit of this vulnerability may lead to a loss of Integrity and/or Availability.(CVE-2024-38797)");

  script_tag(name:"affected", value:"'EDK2' package(s) on Huawei EulerOS Virtualization release 2.13.0.");

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

if(release == "EULEROSVIRT-2.13.0") {

  if(!isnull(res = isrpmvuln(pkg:"edk2-ovmf", rpm:"edk2-ovmf~202011.oe2203sp3~2.13.0.6.70", rls:"EULEROSVIRT-2.13.0"))) {
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
