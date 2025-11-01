# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856521");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2017-15865", "CVE-2022-37032", "CVE-2024-44070");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-22 15:03:00 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"creation_date", value:"2024-09-30 04:00:27 +0000 (Mon, 30 Sep 2024)");
  script_name("openSUSE: Security Advisory for quagga (SUSE-SU-2024:3478-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3478-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UVZ6ERSN5V63IGZLHDTYOHAZWMZUKHHP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga'
  package(s) announced via the SUSE-SU-2024:3478-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for quagga fixes the following issues:

  * CVE-2017-15865: sensitive information disclosed when malformed BGP UPDATE
      packets are processed. (bsc#1230866)

  * CVE-2024-44070: crash when parsing Tunnel Encap attribute due to no length
      check. (bsc#1229438)

  * CVE-2022-37032: out-of-bounds read when parsing a BGP capability message due
      to incorrect size check. (bsc#1202023)");

  script_tag(name:"affected", value:"'quagga' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
