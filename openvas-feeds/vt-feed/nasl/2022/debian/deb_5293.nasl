# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705293");
  script_cve_id("CVE-2022-4174", "CVE-2022-4175", "CVE-2022-4176", "CVE-2022-4177", "CVE-2022-4178", "CVE-2022-4179", "CVE-2022-4180", "CVE-2022-4181", "CVE-2022-4182", "CVE-2022-4183", "CVE-2022-4184", "CVE-2022-4185", "CVE-2022-4186", "CVE-2022-4187", "CVE-2022-4188", "CVE-2022-4189", "CVE-2022-4190", "CVE-2022-4191", "CVE-2022-4192", "CVE-2022-4193", "CVE-2022-4194", "CVE-2022-4195");
  script_tag(name:"creation_date", value:"2022-12-06 02:00:22 +0000 (Tue, 06 Dec 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-01 23:27:00 +0000 (Thu, 01 Dec 2022)");

  script_name("Debian: Security Advisory (DSA-5293)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5293");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5293");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-5293 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Chromium, which could result in the execution of arbitrary code, denial of service or information disclosure.

For the stable distribution (bullseye), these problems have been fixed in version 108.0.5359.71-2~deb11u1.

We recommend that you upgrade your chromium packages.

For the detailed security status of chromium please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);