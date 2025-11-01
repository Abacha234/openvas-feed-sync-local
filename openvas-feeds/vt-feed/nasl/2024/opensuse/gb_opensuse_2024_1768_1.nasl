# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856197");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-4317");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-06-05 01:01:09 +0000 (Wed, 05 Jun 2024)");
  script_name("openSUSE: Security Advisory for postgresql14 (SUSE-SU-2024:1768-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1768-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IIHKOA7LIWU6B6X4Q5PP3I3NLFI3DMSO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql14'
  package(s) announced via the SUSE-SU-2024:1768-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql14 fixes the following issues:

  PostgreSQL upgrade to version 14.12 (bsc#1224051):

  * CVE-2024-4317: Fixed visibility restriction of pg_stats_ext and
      pg_stats_ext_exprs entries to the table owner (bsc#1224038).

  Bug fixes:

  * Fix incompatibility with LLVM 18.

  * Prepare for PostgreSQL 17.

  * Make sure all compilation and doc generation happens in %build.

  * Require LLVM <= 17 for now, because LLVM 18 doesn't seem to work.

  * Remove constraints file because improved memory usage for s390x

  * Use %patch -P N instead of deprecated %patchN.");

  script_tag(name:"affected", value:"'postgresql14' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
