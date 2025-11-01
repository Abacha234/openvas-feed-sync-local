# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705139");
  script_cve_id("CVE-2022-1292");
  script_tag(name:"creation_date", value:"2022-05-19 01:00:08 +0000 (Thu, 19 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-11 20:48:00 +0000 (Wed, 11 May 2022)");

  script_name("Debian: Security Advisory (DSA-5139)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5139");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5139");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openssl");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-5139 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Elison Niven discovered that the c_rehash script included in OpenSSL did not sanitise shell meta characters which could result in the execution of arbitrary commands.

For the oldstable distribution (buster), this problem has been fixed in version 1.1.1n-0+deb10u2.

For the stable distribution (bullseye), this problem has been fixed in version 1.1.1n-0+deb11u2.

We recommend that you upgrade your openssl packages.

For the detailed security status of openssl please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 10, Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);