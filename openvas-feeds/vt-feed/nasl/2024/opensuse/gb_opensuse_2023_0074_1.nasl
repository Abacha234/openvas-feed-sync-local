# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833011");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-31631");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:49:46 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for php8 (SUSE-SU-2023:0074-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0074-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QTL6JMDMLCNO7W5CDGQXOQVBEKX3KCG6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php8'
  package(s) announced via the SUSE-SU-2023:0074-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php8 fixes the following issues:

  - Updated to version 8.0.27:

  - CVE-2022-31631: Fixed an issue where PDO::quote would return an
         unquoted string (bsc#1206958).

     Non-security fixes:

  - Fixed a NULL pointer dereference with -w/-s options.

  - Fixed a crash in Generator when interrupted during argument evaluation
         with extra named params.

  - Fixed a crash in Generator when memory limit was exceeded during
         initialization.

  - Fixed a memory leak in Generator when interrupted during argument
         evaluation.

  - Fixed an issue in the DateTimeZone constructor where an extra null
         byte could be added to the input.

  - Fixed a hang in SaltStack when using php-fpm 8.1.11.

  - Fixed mysqli_query warnings being shown despite using silenced error
         mode.

  - Fixed a NULL pointer dereference when serializing a SOAP response call.");

  script_tag(name:"affected", value:"'php8' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
