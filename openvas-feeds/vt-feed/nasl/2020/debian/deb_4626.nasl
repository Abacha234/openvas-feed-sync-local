# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704626");
  script_cve_id("CVE-2019-11045", "CVE-2019-11046", "CVE-2019-11047", "CVE-2019-11050", "CVE-2020-7059", "CVE-2020-7060");
  script_tag(name:"creation_date", value:"2020-02-19 04:00:20 +0000 (Wed, 19 Feb 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Debian: Security Advisory (DSA-4626)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4626");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4626");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php7.3");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php7.3' package(s) announced via the DSA-4626 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were found in PHP, a widely-used open source general purpose scripting language which could result in information disclosure, denial of service or incorrect validation of path names.

For the stable distribution (buster), these problems have been fixed in version 7.3.14-1~deb10u1.

We recommend that you upgrade your php7.3 packages.

For the detailed security status of php7.3 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'php7.3' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);