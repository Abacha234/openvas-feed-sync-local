# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833124");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-22231", "CVE-2024-22232");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 12:54:54 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for salt (SUSE-SU-2024:0510-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0510-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QSHKCGTTG5ZJ5X5MKFAE34INBTCTPAL5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt'
  package(s) announced via the SUSE-SU-2024:0510-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:

  Security issues fixed:

  * CVE-2024-22231: Prevent directory traversal when creating syndic cache
      directory on the master (bsc#1219430)

  * CVE-2024-22232: Prevent directory traversal attacks in the master's
      serve_file method (bsc#1219431)

  Bugs fixed:

  * Ensure that pillar refresh loads beacons from pillar without restart

  * Fix the aptpkg.py unit test failure

  * Prefer unittest.mock to python-mock in test suite

  * Enable 'KeepAlive' probes for Salt SSH executions (bsc#1211649)

  * Revert changes to set Salt configured user early in the stack (bsc#1216284)

  * Align behavior of some modules when using salt-call via symlink
      (bsc#1215963)

  * Fix gitfs ' **env** ' and improve cache cleaning (bsc#1193948)

  * Remove python-boto dependency for the python3-salt-testsuite package for
      Tumbleweed

  ## Special Instructions and Notes:

  ##");

  script_tag(name:"affected", value:"'salt' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
