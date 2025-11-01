# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704478");
  script_cve_id("CVE-2019-12594", "CVE-2019-7165");
  script_tag(name:"creation_date", value:"2019-07-11 02:00:13 +0000 (Thu, 11 Jul 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-11 03:15:00 +0000 (Thu, 11 Jul 2019)");

  script_name("Debian: Security Advisory (DSA-4478)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4478");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4478");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dosbox' package(s) announced via the DSA-4478 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in the DOSBox emulator, which could result in the execution of arbitrary code on the host running DOSBox when running a malicious executable in the emulator.

For the oldstable distribution (stretch), these problems have been fixed in version 0.74-4.2+deb9u2.

For the stable distribution (buster), these problems have been fixed in version 0.74-2-3+deb10u1.

We recommend that you upgrade your dosbox packages.");

  script_tag(name:"affected", value:"'dosbox' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);