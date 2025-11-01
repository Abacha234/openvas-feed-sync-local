# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893249");
  script_cve_id("CVE-2019-16910", "CVE-2019-18222", "CVE-2020-10932", "CVE-2020-10941", "CVE-2020-16150", "CVE-2020-36421", "CVE-2020-36422", "CVE-2020-36423", "CVE-2020-36424", "CVE-2020-36425", "CVE-2020-36426", "CVE-2020-36475", "CVE-2020-36476", "CVE-2020-36478", "CVE-2021-24119", "CVE-2021-43666", "CVE-2021-44732", "CVE-2022-35409");
  script_tag(name:"creation_date", value:"2022-12-26 02:00:22 +0000 (Mon, 26 Dec 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-29 18:48:00 +0000 (Wed, 29 Dec 2021)");

  script_name("Debian: Security Advisory (DLA-3249)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3249");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3249");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mbedtls");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mbedtls' package(s) announced via the DLA-3249 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in mbedtls, a lightweight crypto and SSL/TLS library, which may allow attackers to obtain sensitive information like the RSA private key or cause a denial of service (application or server crash).

For Debian 10 buster, these problems have been fixed in version 2.16.9-0~deb10u1.

We recommend that you upgrade your mbedtls packages.

For the detailed security status of mbedtls please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mbedtls' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);