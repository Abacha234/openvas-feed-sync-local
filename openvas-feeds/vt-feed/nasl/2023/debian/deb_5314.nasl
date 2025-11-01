# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705314");
  script_cve_id("CVE-2022-45939");
  script_tag(name:"creation_date", value:"2023-01-12 02:00:13 +0000 (Thu, 12 Jan 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-01 19:48:00 +0000 (Thu, 01 Dec 2022)");

  script_name("Debian: Security Advisory (DSA-5314)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5314");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5314");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/emacs");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'emacs' package(s) announced via the DSA-5314 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that missing input sanitising in the ctags functionality of Emacs may result in the execution of arbitrary shell commands.

For the stable distribution (bullseye), this problem has been fixed in version 1:27.1+1-3.1+deb11u1.

We recommend that you upgrade your emacs packages.

For the detailed security status of emacs please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'emacs' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);