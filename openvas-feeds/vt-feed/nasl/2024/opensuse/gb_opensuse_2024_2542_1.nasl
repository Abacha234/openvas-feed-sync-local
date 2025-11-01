# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856317");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-22020", "CVE-2024-27980", "CVE-2024-36138");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-07-24 04:00:30 +0000 (Wed, 24 Jul 2024)");
  script_name("openSUSE: Security Advisory for nodejs18 (SUSE-SU-2024:2542-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2542-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/O76ZOGKLHH4NPWG7FIK7CBBUKVZIITKX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs18'
  package(s) announced via the SUSE-SU-2024:2542-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs18 fixes the following issues:

  Update to 18.20.4:

  * CVE-2024-36138: Fixed CVE-2024-27980 fix bypass (bsc#1227560)

  * CVE-2024-22020: Fixed a bypass of network import restriction via data URL
      (bsc#1227554)

  Changes in 18.20.3:

  * This release fixes a regression introduced in Node.js 18.19.0 where
      http.server.close() was incorrectly closing idle connections. deps:

  * acorn updated to 8.11.3.

  * acorn-walk updated to 8.3.2.

  * ada updated to 2.7.8.

  * c-ares updated to 1.28.1.

  * corepack updated to 0.28.0.

  * nghttp2 updated to 1.61.0.

  * ngtcp2 updated to 1.3.0.

  * npm updated to 10.7.0. Includes a fix from npm@10.5.1 to limit the number of
      open connections npm/cli#7324.

  * simdutf updated to 5.2.4.

  Changes in 18.20.2:

  * CVE-2024-27980: Fixed command injection via args parameter of
      child_process.spawn without shell option enabled on Windows (bsc#1222665)");

  script_tag(name:"affected", value:"'nodejs18' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
