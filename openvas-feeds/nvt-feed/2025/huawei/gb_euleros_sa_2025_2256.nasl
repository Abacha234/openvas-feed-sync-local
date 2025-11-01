# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2256");
  script_cve_id("CVE-2025-27613", "CVE-2025-46334", "CVE-2025-46835", "CVE-2025-48384", "CVE-2025-48386");
  script_tag(name:"creation_date", value:"2025-10-24 04:26:27 +0000 (Fri, 24 Oct 2025)");
  script_version("2025-10-24T05:39:31+0000");
  script_tag(name:"last_modification", value:"2025-10-24 05:39:31 +0000 (Fri, 24 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for git (EulerOS-SA-2025-2256)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2256");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2256");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'git' package(s) announced via the EulerOS-SA-2025-2256 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gitk is a Tcl/Tk based Git history browser. Starting with 1.7.0, when a user clones an untrusted repository and runs gitk without additional command arguments, files for which the user has write permission can be created and truncated. The option Support per-file encoding must have been enabled before in Gitk's Preferences. This option is disabled by default. The same happens when Show origin of this line is used in the main window (regardless of whether Support per-file encoding is enabled or not). This vulnerability is fixed in 2.43.7, 2.44.4, 2.45.4, 2.46.4, 2.47.3, 2.48.2, 2.49.1, and 2.50.1.(CVE-2025-27613)

Git GUI allows you to use the Git source control management tools via a GUI. A malicious repository can ship versions of sh.exe or typical textconv filter programs such as astextplain. Due to the unfortunate design of Tcl on Windows, the search path when looking for an executable always includes the current directory. The mentioned programs are invoked when the user selects Git Bash or Browse Files from the menu. This vulnerability is fixed in 2.43.7, 2.44.4, 2.45.4, 2.46.4, 2.47.3, 2.48.2, 2.49.1, and 2.50.1.(CVE-2025-46334)

Git GUI allows you to use the Git source control management tools via a GUI. When a user clones an untrusted repository and is tricked into editing a file located in a maliciously named directory in the repository, then Git GUI can create and overwrite files for which the user has write permission. This vulnerability is fixed in 2.43.7, 2.44.4, 2.45.4, 2.46.4, 2.47.3, 2.48.2, 2.49.1, and 2.50.1.(CVE-2025-46835)

Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.(CVE-2025-48384)

Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. The wincred credential helper uses a static buffer (target) as a unique key for storing and comparing against internal storage. This credential helper does not properly bounds check the available space remaining in the buffer before appending to it with wcsncat(), leading to potential buffer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'git' package(s) on Huawei EulerOS V2.0SP13(x86_64).");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP13-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~2.33.0~13.h6.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.33.0~13.h6.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-help", rpm:"git-help~2.33.0~13.h6.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git", rpm:"perl-Git~2.33.0~13.h6.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
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
