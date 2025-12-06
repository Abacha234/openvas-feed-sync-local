# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.136443");
  script_version("2025-12-05T05:44:55+0000");
  script_tag(name:"last_modification", value:"2025-12-05 05:44:55 +0000 (Fri, 05 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-11-03 14:52:21 +0000 (Mon, 03 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2025-52099");

  script_name("SQLite <= 3.50 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");

  script_tag(name:"summary", value:"SQLite is prone to a denial of service (DoS) vulnerability.

  Note: This VT has been deprecated as the attached CVE has been rejected as a duplicate of
  CVE-2025-29088. This older CVE is already covered in the VT 'SQLite <= 3.49.0 DoS Vulnerability'
  (OID: 1.3.6.1.4.1.25623.1.0.128119).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow vulnerability allows a remote attacker to
  cause a denial of service via the setupLookaside function.");

  script_tag(name:"affected", value:"SQLite version 3.50.0 and prior.");

  script_tag(name:"solution", value:"No solution is required.

  Note: This VT is deprecated and thus doesn't require a solution.");

  script_xref(name:"URL", value:"https://github.com/SCREAMBBY/CVE-2025-52099");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-chjr-9v3v-pr2f");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
