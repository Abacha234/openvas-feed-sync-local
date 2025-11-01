# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705355");
  script_cve_id("CVE-2022-46871", "CVE-2022-46877", "CVE-2023-0430", "CVE-2023-0616", "CVE-2023-0767", "CVE-2023-23598", "CVE-2023-23601", "CVE-2023-23602", "CVE-2023-23603", "CVE-2023-23605", "CVE-2023-25728", "CVE-2023-25729", "CVE-2023-25730", "CVE-2023-25732", "CVE-2023-25735", "CVE-2023-25737", "CVE-2023-25739", "CVE-2023-25742", "CVE-2023-25744", "CVE-2023-25746");
  script_tag(name:"creation_date", value:"2023-02-19 02:00:16 +0000 (Sun, 19 Feb 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 18:40:00 +0000 (Wed, 04 Jan 2023)");

  script_name("Debian: Security Advisory (DSA-5355)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5355");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5355");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/thunderbird");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'thunderbird' package(s) announced via the DSA-5355 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird, which could result in denial of service or the execution of arbitrary code.

For the stable distribution (bullseye), these problems have been fixed in version 1:102.8.0-1~deb11u1.

We recommend that you upgrade your thunderbird packages.

For the detailed security status of thunderbird please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);