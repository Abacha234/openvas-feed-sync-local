# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.305597598407");
  script_cve_id("CVE-2025-27151", "CVE-2025-46817", "CVE-2025-46818", "CVE-2025-46819", "CVE-2025-49844");
  script_tag(name:"creation_date", value:"2025-10-13 04:05:45 +0000 (Mon, 13 Oct 2025)");
  script_version("2025-10-14T05:39:29+0000");
  script_tag(name:"last_modification", value:"2025-10-14 05:39:29 +0000 (Tue, 14 Oct 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-07 15:40:02 +0000 (Tue, 07 Oct 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-3055a5b407)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-3055a5b407");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-3055a5b407");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402051");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'valkey' package(s) announced via the FEDORA-2025-3055a5b407 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Valkey 8.0.6** - Released Fri 03 October 2025


Upgrade urgency SECURITY: This release includes security fixes we recommend you
apply as soon as possible.

Security fixes

* **CVE-2025-49844** A Lua script may lead to remote code execution
* **CVE-2025-46817** A Lua script may lead to integer overflow and potential RCE
* **CVE-2025-46818** A Lua script can be executed in the context of another user
* **CVE-2025-46819** LUA out-of-bound read

Bug fixes

* Fix accounting for dual channel RDB bytes in replication stats (#2616)
* Minor fix for dual rdb channel connection conn error log (#2658)
* Fix unsigned difference expression compared to zero (#2101)

----

**Valkey 8.0.5** - Released Thu 22 Aug 2025

Upgrade urgency SECURITY: This release includes security fixes we recommend you
apply as soon as possible.

Bug fixes

* Fix clients remaining blocked when reprocessing commands after certain
 blocking operations (#2109)
* Fix a memory corruption issue in the sharded pub/sub unsubscribe logic (#2137)
* Fix potential memory leak by ensuring module context is freed when `aux_save2`
 callback writes no data (#2132)
* Fix `CLIENT UNBLOCK` triggering unexpected errors when used on paused clients
 (#2117)
* Fix missing NULL check on `SSL_new()` when creating outgoing TLS connections
 (#2140)
* Fix incorrect casting of ping extension lengths to prevent silent packet drops
 (#2144)
* Fix replica failover stall due to outdated config epoch (#2178)
* Fix incorrect port/tls-port info in `CLUSTER SLOTS`/`CLUSTER NODES` after
 dynamic config change (#2186)
* Ensure empty error tables in Lua scripts don't crash Valkey (#2229)
* Fix client tracking memory overhead calculation (#2360)
* Handle divergent shard-id from nodes.conf and reconcile to the primary node's
 shard-id (#2174)
* Fix pre-size hashtables per slot when reading RDB files (#2466)

Behavior changes

* Trigger election immediately during a forced manual failover (`CLUSTER
 FAILOVER FORCE`) to avoid delay (#1067)
* Reset ongoing election state when initiating a new manual failover (#1274)

Logging and Tooling Improvements

* Add support to drop all cluster packets (#1252)
* Improve log clarity in failover auth denial message (#1341)

Security fixes

* **CVE-2025-27151**: Check length of AOF file name in valkey-check-aof and reject
 paths longer than `PATH_MAX` (#2146)");

  script_tag(name:"affected", value:"'valkey' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"valkey", rpm:"valkey~8.0.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-compat-redis", rpm:"valkey-compat-redis~8.0.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-compat-redis-devel", rpm:"valkey-compat-redis-devel~8.0.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-debuginfo", rpm:"valkey-debuginfo~8.0.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-debugsource", rpm:"valkey-debugsource~8.0.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-devel", rpm:"valkey-devel~8.0.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-doc", rpm:"valkey-doc~8.0.6~1.fc42", rls:"FC42"))) {
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
