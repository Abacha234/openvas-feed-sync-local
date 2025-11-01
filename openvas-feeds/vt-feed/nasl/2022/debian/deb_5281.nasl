# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705281");
  script_cve_id("CVE-2022-41741", "CVE-2022-41742");
  script_tag(name:"creation_date", value:"2022-11-17 02:00:20 +0000 (Thu, 17 Nov 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-24 17:11:00 +0000 (Mon, 24 Oct 2022)");

  script_name("Debian: Security Advisory (DSA-5281)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5281");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5281");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/nginx");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nginx' package(s) announced via the DSA-5281 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that parsing errors in the mp4 module of Nginx, a high-performance web and reverse proxy server, could result in denial of service, memory disclosure or potentially the execution of arbitrary code when processing a malformed mp4 file.

This module is only enabled in the nginx-extras binary package.

For the stable distribution (bullseye), these problems have been fixed in version 1.18.0-6.1+deb11u3.

We recommend that you upgrade your nginx packages.

For the detailed security status of nginx please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'nginx' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);