# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705335");
  script_cve_id("CVE-2022-21618", "CVE-2022-21619", "CVE-2022-21624", "CVE-2022-21628", "CVE-2022-39399", "CVE-2023-21835", "CVE-2023-21843");
  script_tag(name:"creation_date", value:"2023-02-03 02:00:13 +0000 (Fri, 03 Feb 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-18 00:15:00 +0000 (Wed, 18 Jan 2023)");

  script_name("Debian: Security Advisory (DSA-5335)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5335");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5335");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openjdk-17");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-17' package(s) announced via the DSA-5335 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the OpenJDK Java runtime, which may result in denial of service or spoofing.

For the stable distribution (bullseye), these problems have been fixed in version 17.0.6+10-1~deb11u1.

We recommend that you upgrade your openjdk-17 packages.

For the detailed security status of openjdk-17 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openjdk-17' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);