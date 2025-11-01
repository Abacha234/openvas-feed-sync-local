# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704485");
  script_cve_id("CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2816", "CVE-2019-2842");
  script_tag(name:"creation_date", value:"2019-07-24 02:00:53 +0000 (Wed, 24 Jul 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-06 18:47:00 +0000 (Thu, 06 Oct 2022)");

  script_name("Debian: Security Advisory (DSA-4485)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4485");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4485");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openjdk-8");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-8' package(s) announced via the DSA-4485 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the OpenJDK Java runtime, resulting in information disclosure, denial of service or bypass of sandbox restrictions. In addition the implementation of elliptic curve cryptography was modernised.

For the oldstable distribution (stretch), these problems have been fixed in version 8u222-b10-1~deb9u1.

We recommend that you upgrade your openjdk-8 packages.

For the detailed security status of openjdk-8 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openjdk-8' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);