# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.857029");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2025-24528");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-04 05:00:14 +0000 (Tue, 04 Feb 2025)");
  script_name("openSUSE: Security Advisory for krb5 (SUSE-SU-2025:0343-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0343-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JCK7KMRCHPYDTGOGNNO2XQYYHJRV3F2J");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5'
  package(s) announced via the SUSE-SU-2025:0343-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for krb5 fixes the following issues:

    * CVE-2025-24528: Fixed out-of-bounds write caused by overflow when
      calculating ulog block size can lead to process crash (bsc#1236619).");

  script_tag(name:"affected", value:"'krb5' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
