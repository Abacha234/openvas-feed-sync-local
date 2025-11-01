# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892880");
  script_cve_id("CVE-2021-4140", "CVE-2022-22737", "CVE-2022-22738", "CVE-2022-22739", "CVE-2022-22740", "CVE-2022-22741", "CVE-2022-22742", "CVE-2022-22743", "CVE-2022-22745", "CVE-2022-22747", "CVE-2022-22748", "CVE-2022-22751");
  script_tag(name:"creation_date", value:"2022-01-17 02:00:15 +0000 (Mon, 17 Jan 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-03 20:03:00 +0000 (Tue, 03 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-2880)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2880");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2880");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/firefox-esr");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firefox-esr' package(s) announced via the DLA-2880 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Mozilla Firefox web browser, which could potentially result in the execution of arbitrary code, information disclosure, denial of service or spoofing.

For Debian 9 stretch, these problems have been fixed in version 91.5.0esr-1~deb9u1.

We recommend that you upgrade your firefox-esr packages.

For the detailed security status of firefox-esr please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'firefox-esr' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);