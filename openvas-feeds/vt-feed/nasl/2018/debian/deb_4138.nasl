# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704138");
  script_cve_id("CVE-2017-18187", "CVE-2018-0487", "CVE-2018-0488");
  script_tag(name:"creation_date", value:"2018-03-14 23:00:00 +0000 (Wed, 14 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4138)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4138");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4138");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mbedtls");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mbedtls' package(s) announced via the DSA-4138 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in mbed TLS, a lightweight crypto and SSL/TLS library, that allowed a remote attacker to either cause a denial-of-service by application crash, or execute arbitrary code.

For the stable distribution (stretch), these problems have been fixed in version 2.4.2-1+deb9u2.

We recommend that you upgrade your mbedtls packages.

For the detailed security status of mbedtls please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'mbedtls' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);