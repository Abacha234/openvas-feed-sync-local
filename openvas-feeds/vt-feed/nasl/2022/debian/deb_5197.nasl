# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705197");
  script_cve_id("CVE-2021-22898", "CVE-2021-22924", "CVE-2021-22945", "CVE-2021-22946", "CVE-2021-22947", "CVE-2022-22576", "CVE-2022-27774", "CVE-2022-27775", "CVE-2022-27776", "CVE-2022-27781", "CVE-2022-27782", "CVE-2022-32205", "CVE-2022-32206", "CVE-2022-32207", "CVE-2022-32208");
  script_tag(name:"creation_date", value:"2022-08-03 01:00:21 +0000 (Wed, 03 Aug 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 03:15:00 +0000 (Fri, 15 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-5197)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5197");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5197");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/curl");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'curl' package(s) announced via the DSA-5197 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in cURL, an URL transfer library. These flaws may allow remote attackers to obtain sensitive information, leak authentication or cookie header data or facilitate a denial of service attack.

For the stable distribution (bullseye), these problems have been fixed in version 7.74.0-1.3+deb11u2.

We recommend that you upgrade your curl packages.

For the detailed security status of curl please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'curl' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);