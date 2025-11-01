# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891747");
  script_cve_id("CVE-2018-5383");
  script_tag(name:"creation_date", value:"2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DLA-1747)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1747");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1747");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firmware-nonfree' package(s) announced via the DLA-1747 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eli Biham and Lior Neumann discovered a cryptographic weakness in the Bluetooth LE SC pairing protocol, called the Fixed Coordinate Invalid Curve Attack (CVE-2018-5383). Depending on the devices used, this could be exploited by a nearby attacker to obtain sensitive information, for denial of service, or for other security impact.

This flaw has been fixed in firmware for Intel Wireless 7260 (B3), 7260 (B5), 7265 (D1), and 8264 adapters, and for Qualcomm Atheros QCA61x4 ROME version 3.2 adapters. Other Bluetooth adapters are also affected and remain vulnerable.

For Debian 8 Jessie, this problem has been fixed in version 20161130-5~deb8u1.

We recommend that you upgrade your firmware-nonfree packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'firmware-nonfree' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);