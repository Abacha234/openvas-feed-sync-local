# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845469");
  script_cve_id("CVE-2022-1920", "CVE-2022-1921", "CVE-2022-1922", "CVE-2022-1923", "CVE-2022-1924", "CVE-2022-1925", "CVE-2022-2122");
  script_tag(name:"creation_date", value:"2022-08-09 01:00:29 +0000 (Tue, 09 Aug 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-26 22:30:00 +0000 (Tue, 26 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-5555-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5555-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5555-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gst-plugins-good1.0' package(s) announced via the USN-5555-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GStreamer Good Plugins incorrectly handled certain files.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2022-1920, CVE-2022-1921)

It was discovered that GStreamer Good Plugins incorrectly handled certain files.
An attacker could possibly use this issue to cause a denial of service or
execute arbitrary code. (CVE-2022-1922, CVE-2022-1923, CVE-2022-1924,
CVE-2022-1925, CVE-2022-2122)");

  script_tag(name:"affected", value:"'gst-plugins-good1.0' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
