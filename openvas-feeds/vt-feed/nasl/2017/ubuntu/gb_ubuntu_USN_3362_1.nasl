# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843253");
  script_cve_id("CVE-2017-10971", "CVE-2017-10972", "CVE-2017-2624");
  script_tag(name:"creation_date", value:"2017-07-25 05:24:40 +0000 (Tue, 25 Jul 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Ubuntu: Security Advisory (USN-3362-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3362-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3362-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server, xorg-server-hwe-16.04, xorg-server-lts-xenial' package(s) announced via the USN-3362-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the X.Org X server incorrectly handled endianness
conversion of certain X events. An attacker able to connect to an X server,
either locally or remotely, could use this issue to crash the server, or
possibly execute arbitrary code as an administrator. (CVE-2017-10971)

It was discovered that the X.Org X server incorrectly handled endianness
conversion of certain X events. An attacker able to connect to an X server,
either locally or remotely, could use this issue to possibly obtain
sensitive information. (CVE-2017-10972)

Eric Sesterhenn discovered that the X.Org X server incorrectly compared
MIT cookies. An attacker could possibly use this issue to perform a timing
attack and recover the MIT cookie. (CVE-2017-2624)");

  script_tag(name:"affected", value:"'xorg-server, xorg-server-hwe-16.04, xorg-server-lts-xenial' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
