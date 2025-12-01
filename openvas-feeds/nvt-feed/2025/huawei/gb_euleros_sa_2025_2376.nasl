# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2376");
  script_cve_id("CVE-2025-53905", "CVE-2025-53906");
  script_tag(name:"creation_date", value:"2025-11-12 04:29:57 +0000 (Wed, 12 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2025-2376)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2376");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2376");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2025-2376 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vim is an open source, command line text editor. Prior to version 9.1.1552, a path traversal issue in Vim's tar.vim plugin can allow overwriting of arbitrary files when opening specially crafted tar archives. Impact is low because this exploit requires direct user interaction. However, successfully exploitation can lead to overwriting sensitive files or placing executable code in privileged locations, depending on the permissions of the process editing the archive. The victim must edit such a file using Vim which will reveal the filename and the file content, a careful user may suspect some strange things going on. Successful exploitation could results in the ability to execute arbitrary commands on the underlying operating system. Version 9.1.1552 contains a patch for the vulnerability.(CVE-2025-53905)

Vim is an open source, command line text editor. Prior to version 9.1.1551, a path traversal issue in Vim's zip.vim plugin can allow overwriting of arbitrary files when opening specially crafted zip archives. Impact is low because this exploit requires direct user interaction. However, successfully exploitation can lead to overwriting sensitive files or placing executable code in privileged locations, depending on the permissions of the process editing the archive. The victim must edit such a file using Vim which will reveal the filename and the file content, a careful user may suspect some strange things going on. Successful exploitation could results in the ability to execute arbitrary commands on the underlying operating system. Version 9.1.1551 contains a patch for the vulnerability.(CVE-2025-53906)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS V2.0SP12.");

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

if(release == "EULEROS-2.0SP12") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~9.0~5.h24.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~9.0~5.h24.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~9.0~5.h24.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~9.0~5.h24.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
