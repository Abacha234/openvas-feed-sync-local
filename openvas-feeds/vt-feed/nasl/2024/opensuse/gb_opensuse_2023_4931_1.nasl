# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833619");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-39326", "CVE-2023-45284", "CVE-2023-45285");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 16:27:36 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:21:41 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for go1.21 (SUSE-SU-2023:4931-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4931-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MZFUAUPHUEHDK5KFJ3FLMIUNOHZT54VR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.21'
  package(s) announced via the SUSE-SU-2023:4931-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.21-openssl fixes the following issues:

  Update to version 1.21.5.1:

  * CVE-2023-45285: cmd/go: git VCS qualifier in module path uses git:// scheme
      (bsc#1217834).

  * CVE-2023-45284: path/filepath: Clean removes ending slash for volume on
      Windows in Go 1.21.4 (bsc#1216943).

  * CVE-2023-39326: net/http: limit chunked data overhead (bsc#1217833).

  * cmd/go: go mod download needs to support toolchain upgrades

  * cmd/compile: invalid pointer found on stack when compiled with -race

  * os: NTFS deduped file changed from regular to irregular

  * net: TCPConn.ReadFrom hangs when io.Reader is TCPConn or UnixConn, Linux
      kernel   5.1

  * cmd/compile: internal compiler error: panic during prove while compiling:
      unexpected induction with too many parents

  * syscall: TestOpenFileLimit unintentionally runs on non-Unix platforms

  * runtime: self-deadlock on mheap_.lock

  * crypto/rand: Legacy RtlGenRandom use on Windows

  ##");

  script_tag(name:"affected", value:"'go1.21' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
