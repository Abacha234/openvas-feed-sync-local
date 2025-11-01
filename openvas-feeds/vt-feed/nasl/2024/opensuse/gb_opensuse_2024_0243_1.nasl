# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856341");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-27305", "CVE-2024-34083");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-22 15:02:31 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-08-17 04:00:22 +0000 (Sat, 17 Aug 2024)");
  script_name("openSUSE: Security Advisory for python (openSUSE-SU-2024:0243-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0243-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/G642S3M3RN5DHIPCAJBHQAPH7Q6QWPX2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the openSUSE-SU-2024:0243-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-aiosmtpd fixes the following issues:

  - CVE-2024-34083: Fixed MiTM attack could inject extra unencrypted
       commands after STARTTLS (boo#1224467)

  - CVE-2024-27305: Fixed SMTP smuggling (boo#1221328)");

  script_tag(name:"affected", value:"'python' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
