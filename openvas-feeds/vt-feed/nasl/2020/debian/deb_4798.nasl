# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704798");
  script_cve_id("CVE-2020-28984", "CVE-2022-28959", "CVE-2022-28960", "CVE-2022-28961");
  script_tag(name:"creation_date", value:"2020-11-26 04:00:07 +0000 (Thu, 26 Nov 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-04 15:05:00 +0000 (Thu, 04 Feb 2021)");

  script_name("Debian: Security Advisory (DSA-4798)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4798");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4798");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/spip");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'spip' package(s) announced via the DSA-4798 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that SPIP, a website engine for publishing, did not correctly validate its input. This would allow authenticated users to execute arbitrary code.

For the stable distribution (buster), this problem has been fixed in version 3.2.4-1+deb10u3.

We recommend that you upgrade your spip packages.

For the detailed security status of spip please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'spip' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);