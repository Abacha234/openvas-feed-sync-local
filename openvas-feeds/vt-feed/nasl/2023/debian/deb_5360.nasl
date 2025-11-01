# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705360");
  script_cve_id("CVE-2022-48337", "CVE-2022-48338", "CVE-2022-48339");
  script_tag(name:"creation_date", value:"2023-02-25 02:00:06 +0000 (Sat, 25 Feb 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-02 16:08:00 +0000 (Thu, 02 Mar 2023)");

  script_name("Debian: Security Advisory (DSA-5360)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5360");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5360");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/emacs");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'emacs' package(s) announced via the DSA-5360 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xi Lu discovered that missing input sanitising in Emacs (in etags, the Ruby mode and htmlfontify) could result in the execution of arbitrary shell commands.

For the stable distribution (bullseye), these problems have been fixed in version 1:27.1+1-3.1+deb11u2.

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