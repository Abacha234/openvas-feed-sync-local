# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856843");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-2153", "CVE-2024-21538");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 19:38:05 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-13 05:00:33 +0000 (Fri, 13 Dec 2024)");
  script_name("openSUSE: Security Advisory for nodejs20 (SUSE-SU-2024:4300-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4300-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/F5MWHLSLJN7Y33H7KG3YV7HOL6RE67PG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs20'
  package(s) announced via the SUSE-SU-2024:4300-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs20 fixes the following issues:

  * CVE-2024-21538: Fixed regular expression denial of service in cross-spawn
      dependency (bsc#1233856)

  Other fixes: \- Updated to 20.18.1: * Experimental Network Inspection Support in
  Node.js * Exposes X509_V_FLAG_PARTIAL_CHAIN to tls.createSecureContext * New
  option for vm.createContext() to create a context with a freezable globalThis *
  buffer: optimize createFromString \- Changes in 20.17.0: * module: support
  require()ing synchronous ESM graphs * path: add matchesGlob method * stream:
  expose DuplexPair API \- Changes in 20.16.0: * process: add
  process.getBuiltinModule(id) * inspector: fix disable async hooks on
  Debugger.setAsyncCallStackDepth * buffer: add .bytes() method to Blob");

  script_tag(name:"affected", value:"'nodejs20' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
