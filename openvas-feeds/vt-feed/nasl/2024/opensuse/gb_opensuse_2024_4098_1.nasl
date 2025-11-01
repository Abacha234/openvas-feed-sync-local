# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856745");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-10976", "CVE-2024-10977", "CVE-2024-10978", "CVE-2024-10979");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-11-29 05:00:22 +0000 (Fri, 29 Nov 2024)");
  script_name("openSUSE: Security Advisory for postgresql15 (SUSE-SU-2024:4098-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4098-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WZ4XCJSD4XKNYKEZ45SUQC74UWPFY4NM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql15'
  package(s) announced via the SUSE-SU-2024:4098-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql15 fixes the following issues:

  * CVE-2024-10976: Ensure cached plans are marked as dependent on the calling
      role when RLS applies to a non-top-level table reference (bsc#1233323).

  * CVE-2024-10977: Make libpq discard error messages received during SSL or GSS
      protocol negotiation (bsc#1233325).

  * CVE-2024-10978: Fix unintended interactions between SET SESSION
      AUTHORIZATION and SET ROLE (bsc#1233326).

  * CVE-2024-10979: Prevent trusted PL/Perl code from changing environment
      variables (bsc#1233327).");

  script_tag(name:"affected", value:"'postgresql15' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
