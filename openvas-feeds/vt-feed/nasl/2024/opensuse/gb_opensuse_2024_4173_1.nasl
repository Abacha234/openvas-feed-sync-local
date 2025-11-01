# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856789");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-10976", "CVE-2024-10977", "CVE-2024-10978", "CVE-2024-10979");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-12-05 05:00:27 +0000 (Thu, 05 Dec 2024)");
  script_name("openSUSE: Security Advisory for postgresql, postgresql16, postgresql17 (SUSE-SU-2024:4173-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4173-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5WIRX4CKTVOW2ASMEMI4CQRBL6C6VQJS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql, postgresql16, postgresql17'
  package(s) announced via the SUSE-SU-2024:4173-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql, postgresql16, postgresql17 fixes the following
  issues:

  This update ships postgresql17 , and fixes security issues with postgresql16:

  * bsc#1230423: Relax the dependency of extensions on the server version from
      exact major.minor to greater or equal, after Tom Lane confirmed on the
      PostgreSQL packagers list that ABI stability is being taken care of between
      minor releases.

  * bsc#1219340: The last fix was not correct. Improve it by removing the
      dependency again and call fillup only if it is installed.

  postgresql16 was updated to 16.6: * Repair ABI break for extensions that work
  with struct ResultRelInfo. * Restore functionality of ALTER {ROLEDATABASE} SET
  role. * Fix cases where a logical replication slot's restart_lsn could go
  backwards. * Avoid deleting still-needed WAL files during pg_rewind. * Fix race
  conditions associated with dropping shared statistics entries. * Count index
  scans in contrib/bloom indexes in the statistics views, such as the
  pg_stat_user_indexes.idx_scan counter. * Fix crash when checking to see if an
  index's opclass options have changed. * Avoid assertion failure caused by
  disconnected NFA sub-graphs in regular expression parsing.
  postgresql16 was updated to 16.5:

  * CVE-2024-10976, bsc#1233323: Ensure cached plans are marked as dependent on
      the calling role when RLS applies to a non-top-level table reference.

  * CVE-2024-10977, bsc#1233325: Make libpq discard error messages received
      during SSL or GSS protocol negotiation.

  * CVE-2024-10978, bsc#1233326: Fix unintended interactions between SET SESSION
      AUTHORIZATION and SET ROLE

  * CVE-2024-10979, bsc#1233327: Prevent trusted PL/Perl code from changing
      environment variables.

  * Don't build the libs and mini flavor anymore to hand over to PostgreSQL 17.

  postgresql17 is shipped in version 17.2:

  * CVE-2024-10976, bsc#1233323: Ensure cached plans are marked as dependent on
      the calling role when RLS applies to a non-top-level table reference.

  * CVE-2024-10977, bsc#1233325: Make libpq discard error messages received
      during SSL or GSS protocol negotiation.

  * CVE-2024-10978, bsc#1233326: Fix unintended interactions between SET SESSION
      AUTHORIZATION and SET ROLE

  * CVE-2024-10979, bsc#123332 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'postgresql, postgresql16, postgresql17' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
