# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705125");
  script_cve_id("CVE-2022-1477", "CVE-2022-1478", "CVE-2022-1479", "CVE-2022-1481", "CVE-2022-1482", "CVE-2022-1483", "CVE-2022-1484", "CVE-2022-1485", "CVE-2022-1486", "CVE-2022-1487", "CVE-2022-1488", "CVE-2022-1489", "CVE-2022-1490", "CVE-2022-1491", "CVE-2022-1492", "CVE-2022-1493", "CVE-2022-1494", "CVE-2022-1495", "CVE-2022-1496", "CVE-2022-1497", "CVE-2022-1498", "CVE-2022-1499", "CVE-2022-1500", "CVE-2022-1501");
  script_tag(name:"creation_date", value:"2022-04-29 01:00:26 +0000 (Fri, 29 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-29 02:35:00 +0000 (Fri, 29 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-5125)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5125");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5125");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-5125 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Chromium, which could result in the execution of arbitrary code, denial of service or information disclosure.

For the stable distribution (bullseye), these problems have been fixed in version 101.0.4951.41-1~deb11u1.

We recommend that you upgrade your chromium packages.

For the detailed security status of chromium please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);