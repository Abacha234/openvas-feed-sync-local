# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2393");
  script_cve_id("CVE-2024-13978", "CVE-2025-8177");
  script_tag(name:"creation_date", value:"2025-11-12 04:29:57 +0000 (Wed, 12 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-11 16:57:45 +0000 (Thu, 11 Sep 2025)");

  script_name("Huawei EulerOS: Security Advisory for libtiff (EulerOS-SA-2025-2393)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2393");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2393");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libtiff' package(s) announced via the EulerOS-SA-2025-2393 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in LibTIFF up to 4.7.0. It has been declared as problematic. Affected by this vulnerability is the function t2p_read_tiff_init of the file tools/tiff2pdf.c of the component fax2ps. The manipulation leads to null pointer dereference. The attack needs to be approached locally. The complexity of an attack is rather high. The exploitation appears to be difficult. The patch is named 2ebfffb0e8836bfb1cd7d85c059cd285c59761a4. It is recommended to apply a patch to fix this issue.(CVE-2024-13978)

A vulnerability was found in LibTIFF up to 4.7.0. It has been rated as critical. This issue affects the function setrow of the file tools/thumbnail.c. The manipulation leads to buffer overflow. An attack has to be approached locally. The patch is named e8c9d6c616b19438695fd829e58ae4fde5bfbc22. It is recommended to apply a patch to fix this issue. This vulnerability only affects products that are no longer supported by the maintainer.(CVE-2025-8177)");

  script_tag(name:"affected", value:"'libtiff' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

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

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.1.0~1.h34.r5.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
