# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886766");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-4558", "CVE-2024-4559", "CVE-2023-49528", "CVE-2024-31578", "CVE-2024-31581", "CVE-2024-31582", "CVE-2024-31585", "CVE-2023-49501", "CVE-2023-49502", "CVE-2023-51791", "CVE-2023-51792", "CVE-2023-51793", "CVE-2023-51795", "CVE-2023-51796", "CVE-2023-51797", "CVE-2023-51798", "CVE-2023-50007", "CVE-2023-50008", "CVE-2023-50009", "CVE-2023-50010", "CVE-2024-4331", "CVE-2024-4368");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-05-27 10:46:44 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2024-55e7e839f1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-55e7e839f1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IPETICRXUOGRIM4U3BCRTIKE3IZWCSBT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2024-55e7e839f1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
