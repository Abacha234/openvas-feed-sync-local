# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833383");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2007-4559", "CVE-2023-24329");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-27 19:28:52 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:55:52 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for python311 (SUSE-SU-2023:2937-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2937-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JCTDOFIDEDUSO3NJXNN6H36O4IU4CXN6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python311'
  package(s) announced via the SUSE-SU-2023:2937-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python311 fixes the following issues:

  python was updated to version 3.11.4:

  * CVE-2023-24329: Fixed blocklist bypass via the urllib.parse component when
      supplying a URL that starts with blank characters (bsc#1208471).

  * CVE-2007-4559: Fixed python tarfile module directory traversal
      (bsc#1203750).

  * Fixed a security in flaw in uu.decode() that could allow for directory
      traversal based on the input if no out_file was specified.

  * Do not expose the local on-disk location in directory indexes produced by
      http.client.SimpleHTTPRequestHandler.

  Bugfixes:

  * trace. **main** now uses io.open_code() for files to be executed instead of
      raw open().

  ##");

  script_tag(name:"affected", value:"'python311' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
