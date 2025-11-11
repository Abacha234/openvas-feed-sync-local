# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.20921.1");
  script_cve_id("CVE-2025-55159");
  script_tag(name:"creation_date", value:"2025-11-10 04:16:56 +0000 (Mon, 10 Nov 2025)");
  script_version("2025-11-10T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-11-10 05:40:50 +0000 (Mon, 10 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:20921-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:20921-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202520921-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248004");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023169.html");
  script_xref(name:"URL", value:"https://rust-random.github.io/book/guide-seeding.html#a-simple-number");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Recommended update of flake-pilot' package(s) announced via the SUSE-SU-2025:20921-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for flake-pilot fixes the following issues:

Update version to 3.1.22.

- Fixes to use flakes as normal user

 Running a flake is a container based instance provisioning
 and startup. Some part of this process requires root permissions
 for example mounting the container instance store for the
 provisioning step. This commit fixes the required calls to
 be properly managed by sudo.

- seed from entropy

- Fix assignment of random sequence number

 We should use a seed for the sequence as described in
 [link moved to references]
 In addition the logic when a random sequence number should
 be used was wrong and needed a fix regarding resume and
 attach type flakes which must not use a random sequence

- Pass --init option for resume type flakes

 In resume mode a sleep command is used to keep the container
 open. However, without the --init option there is no signal
 handling available. This commit fixes it

- Revert 'kill prior remove when using %remove flag'

 This reverts commit 06c7d4aa71f74865dfecba399fd08cc2fde2e1f2.
 no hard killing needed with the event loop entrypoint

- Fixed CVE-2025-55159 slab: incorrect bounds check

 Update to slab 0.4.11 to fix the mentioned CVE.
 This Fixes bsc#1248004

- Apply clippy fixes

- Create sequence number for the same invocation

 If a flake which is not a resume or attach flake is called twice
 with the same invocation arguments an error message is displayed
 to give this invocation a new name via the @NAME runtime option.
 This commit makes this more comfortable and automatically assigns
 a random sequence number for the call if no @NAME is given.

- kill prior remove when using %remove flag

 In case the container instance should be removed via the %remove
 flag, send a kill first, followed by a force remove. The reason
 for this is because we use a never ending sleep command as entry
 point for resume type containers. If they should be removed the
 standard signal send on podman rm will not stop the sleep and
 after a period of 10 seconds podman sends a kill signal itself.
 We can speedup this process as we know the entry point command
 and send the kill signal first followed by the remove which
 saves us some wait time spent in podman otherwise.

- Fix clippy hints

 variables can be used directly in the format! string

- Prune old images after load

 Make sure no <none> image references stay in the registry");

  script_tag(name:"affected", value:"'Recommended update of flake-pilot' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"flake-pilot", rpm:"flake-pilot~3.1.22~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flake-pilot-podman", rpm:"flake-pilot-podman~3.1.22~160000.1.1", rls:"SLES16.0.0"))) {
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
