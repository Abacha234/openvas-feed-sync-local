# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856740");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-40866", "CVE-2024-44185", "CVE-2024-44187", "CVE-2024-44244", "CVE-2024-44296");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-25 13:25:52 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-11-28 05:00:20 +0000 (Thu, 28 Nov 2024)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2024:4084-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4084-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BM3TEF6EKEHPOEHOTLRUSB667KVXK3EM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2024:4084-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  Update to version 2.46.3 (bsc#1232747):

  * CVE-2024-44244: Processing maliciously crafted web content may lead to an
      unexpected process crash.

  * CVE-2024-44296: Processing maliciously crafted web content may prevent
      Content Security Policy from being enforced.

  * CVE-2024-40866: Visiting a malicious website may lead to address bar
      spoofing.

  New references to version 2.46.0 (boo#1231039):

  * CVE-2024-44187: A cross- origin issue existed with iframe elements. This
      was addressed with improved tracking of security origins.

  * CVE-2024-44185: Processing maliciously crafted web content may lead to an
      unexpected process crash.");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
