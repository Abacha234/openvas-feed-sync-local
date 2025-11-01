# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704248");
  script_cve_id("CVE-2017-12081", "CVE-2017-12082", "CVE-2017-12086", "CVE-2017-12099", "CVE-2017-12100", "CVE-2017-12101", "CVE-2017-12102", "CVE-2017-12103", "CVE-2017-12104", "CVE-2017-12105", "CVE-2017-2899", "CVE-2017-2900", "CVE-2017-2901", "CVE-2017-2902", "CVE-2017-2903", "CVE-2017-2904", "CVE-2017-2905", "CVE-2017-2906", "CVE-2017-2907", "CVE-2017-2908", "CVE-2017-2918");
  script_tag(name:"creation_date", value:"2018-07-16 22:00:00 +0000 (Mon, 16 Jul 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-13 19:05:00 +0000 (Mon, 13 Jun 2022)");

  script_name("Debian: Security Advisory (DSA-4248)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4248");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4248");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/blender");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'blender' package(s) announced via the DSA-4248 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in various parsers of Blender, a 3D modeller/ renderer. Malformed .blend model files and malformed multimedia files (AVI, BMP, HDR, CIN, IRIS, PNG, TIFF) may result in the execution of arbitrary code.

For the stable distribution (stretch), these problems have been fixed in version 2.79.b+dfsg0-1~deb9u1.

We recommend that you upgrade your blender packages.

For the detailed security status of blender please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'blender' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);