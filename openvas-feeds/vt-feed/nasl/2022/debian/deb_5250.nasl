# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705250");
  script_cve_id("CVE-2022-42010", "CVE-2022-42011", "CVE-2022-42012");
  script_tag(name:"creation_date", value:"2022-10-08 01:00:05 +0000 (Sat, 08 Oct 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-11 18:51:00 +0000 (Tue, 11 Oct 2022)");

  script_name("Debian: Security Advisory (DSA-5250)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5250");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5250");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dbus");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dbus' package(s) announced via the DSA-5250 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Evgeny Vereshchagin discovered multiple vulnerabilities in D-Bus, a simple interprocess messaging system, which may result in denial of service by an authenticated user.

For the stable distribution (bullseye), these problems have been fixed in version 1.12.24-0+deb11u1.

We recommend that you upgrade your dbus packages.

For the detailed security status of dbus please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'dbus' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);