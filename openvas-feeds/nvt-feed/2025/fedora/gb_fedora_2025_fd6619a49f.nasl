# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10210066199749102");
  script_cve_id("CVE-2025-46817", "CVE-2025-46818", "CVE-2025-46819", "CVE-2025-49844");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-07 15:40:02 +0000 (Tue, 07 Oct 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-fd6619a49f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-fd6619a49f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-fd6619a49f");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'valkey' package(s) announced via the FEDORA-2025-fd6619a49f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Valkey 8.1.4**

Upgrade urgency SECURITY: This release includes security fixes we recommend you
apply as soon as possible.

Security fixes

* **CVE-2025-49844** A Lua script may lead to remote code execution
* **CVE-2025-46817** A Lua script may lead to integer overflow and potential RCE
* **CVE-2025-46818** A Lua script can be executed in the context of another user
* **CVE-2025-46819** LUA out-of-bound read

Bug fixes

* Fix accounting for dual channel RDB bytes in replication stats (#2614)
* Fix EVAL to report unknown error when empty error table is provided (#2229)
* Fix use-after-free when active expiration triggers hashtable to shrink (#2257)
* Fix MEMORY USAGE to account for embedded keys (#2290)
* Fix memory leak when shrinking a hashtable without entries (#2288)
* Prevent potential assertion in active defrag handling large allocations (#2353)
* Prevent bad memory access when NOTOUCH client gets unblocked (#2347)
* Converge divergent shard-id persisted in nodes.conf to primary's shard id (#2174)
* Fix client tracking memory overhead calculation (#2360)
* Fix RDB load per slot memory pre-allocation when loading from RDB snapshot (#2466)
* Don't use AVX2 instructions if the CPU doesn't support it (#2571)
* Fix bug where active defrag may be unable to defrag sparsely filled pages (#2656)

Packaging changes

* add new sub-package **valkey-tls** for the TLS encryption module, which was previously built into main valkey
* add new sub-package **valkey-rdma** for the RDMA (Remote Direct Memory Access ) module, this a new optional feature");

  script_tag(name:"affected", value:"'valkey' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"valkey", rpm:"valkey~8.1.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-compat-redis", rpm:"valkey-compat-redis~8.1.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-compat-redis-devel", rpm:"valkey-compat-redis-devel~8.1.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-debuginfo", rpm:"valkey-debuginfo~8.1.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-debugsource", rpm:"valkey-debugsource~8.1.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-devel", rpm:"valkey-devel~8.1.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-doc", rpm:"valkey-doc~8.1.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-rdma", rpm:"valkey-rdma~8.1.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-rdma-debuginfo", rpm:"valkey-rdma-debuginfo~8.1.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-tls", rpm:"valkey-tls~8.1.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-tls-debuginfo", rpm:"valkey-tls-debuginfo~8.1.4~2.fc43", rls:"FC43"))) {
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
