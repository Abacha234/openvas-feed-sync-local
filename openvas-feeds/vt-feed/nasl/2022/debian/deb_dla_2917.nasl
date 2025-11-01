# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892917");
  script_cve_id("CVE-2022-21248", "CVE-2022-21282", "CVE-2022-21283", "CVE-2022-21293", "CVE-2022-21294", "CVE-2022-21296", "CVE-2022-21299", "CVE-2022-21305", "CVE-2022-21340", "CVE-2022-21341", "CVE-2022-21349", "CVE-2022-21360", "CVE-2022-21365");
  script_tag(name:"creation_date", value:"2022-02-11 02:00:20 +0000 (Fri, 11 Feb 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-25 15:15:00 +0000 (Tue, 25 Jan 2022)");

  script_name("Debian: Security Advisory (DLA-2917)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2917");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2917");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openjdk-8");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-8' package(s) announced via the DLA-2917 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the OpenJDK Java runtime, which may result in denial of service, bypass of deserialization restrictions or information disclosure.

For Debian 9 stretch, these problems have been fixed in version 8u322-b06-1~deb9u1.

We recommend that you upgrade your openjdk-8 packages.

For the detailed security status of openjdk-8 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'openjdk-8' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);