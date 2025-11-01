# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704893");
  script_cve_id("CVE-2021-3472");
  script_tag(name:"creation_date", value:"2021-04-20 03:00:07 +0000 (Tue, 20 Apr 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-19 12:54:00 +0000 (Wed, 19 May 2021)");

  script_name("Debian: Security Advisory (DSA-4893)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4893");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4893");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xorg-server");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xorg-server' package(s) announced via the DSA-4893 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan-Niklas Sohn discovered that missing input sanitising in the XInput extension of the X.org X server may result in privilege escalation if the X server is running privileged.

For the stable distribution (buster), this problem has been fixed in version 2:1.20.4-1+deb10u3.

We recommend that you upgrade your xorg-server packages.

For the detailed security status of xorg-server please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);