# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705257");
  script_cve_id("CVE-2021-4037", "CVE-2022-0171", "CVE-2022-1184", "CVE-2022-20421", "CVE-2022-2602", "CVE-2022-2663", "CVE-2022-3061", "CVE-2022-3176", "CVE-2022-3303", "CVE-2022-39188", "CVE-2022-39842", "CVE-2022-40307", "CVE-2022-41674", "CVE-2022-42719", "CVE-2022-42720", "CVE-2022-42721", "CVE-2022-42722");
  script_tag(name:"creation_date", value:"2022-10-20 01:00:18 +0000 (Thu, 20 Oct 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 14:06:00 +0000 (Tue, 18 Oct 2022)");

  script_name("Debian: Security Advisory (DSA-5257)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5257");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5257-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5257 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The security update announced as DSA 5257-1 caused regressions on certain systems using the amdgpu driver. Updated packages are now available to correct this issue.

For the stable distribution (bullseye), this problem has been fixed in version 5.10.149-2.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);