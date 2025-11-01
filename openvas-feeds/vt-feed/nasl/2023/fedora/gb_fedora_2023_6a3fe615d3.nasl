# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885426");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-45866");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-18 18:41:00 +0000 (Mon, 18 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-10 02:16:53 +0000 (Sun, 10 Dec 2023)");
  script_name("Fedora: Security Advisory for bluez (FEDORA-2023-6a3fe615d3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-6a3fe615d3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/D2N2P5LMP3V7IJONALV2KOFL4NUU23CJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez'
  package(s) announced via the FEDORA-2023-6a3fe615d3 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Utilities for use in Bluetooth applications:

  - avinfo

  - bluemoon

  - bluetoothctl

  - bluetoothd

  - btattach

  - btmon

  - hex2hcd

  - l2ping

  - l2test

  - mpris-proxy

  - rctest

The BLUETOOTH trademarks are owned by Bluetooth SIG, Inc., U.S.A.");

  script_tag(name:"affected", value:"'bluez' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
