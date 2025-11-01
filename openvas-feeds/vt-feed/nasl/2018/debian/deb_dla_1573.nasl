# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891573");
  script_cve_id("CVE-2016-0801", "CVE-2017-0561", "CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-9417");
  script_tag(name:"creation_date", value:"2018-11-12 23:00:00 +0000 (Mon, 12 Nov 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DLA-1573)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1573");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1573");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firmware-nonfree' package(s) announced via the DLA-1573 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the firmware for Broadcom BCM43xx wifi chips that may lead to a privilege escalation or loss of confidentiality.

CVE-2016-0801

Broadgate Team discovered flaws in packet processing in the Broadcom wifi firmware and proprietary drivers that could lead to remote code execution. However, this vulnerability is not believed to affect the drivers used in Debian.

CVE-2017-0561

Gal Beniamini of Project Zero discovered a flaw in the TDLS implementation in Broadcom wifi firmware. This could be exploited by an attacker on the same WPA2 network to execute code on the wifi microcontroller.

CVE-2017-9417 / #869639 Nitay Artenstein of Exodus Intelligence discovered a flaw in the WMM implementation in Broadcom wifi firmware. This could be exploited by a nearby attacker to execute code on the wifi microcontroller.

CVE-2017-13077 / CVE-2017-13078 / CVE-2017-13079 / CVE-2017-13080 / CVE-2017-13081 Mathy Vanhoef of the imec-DistriNet research group of KU Leuven discovered multiple vulnerabilities in the WPA protocol used for authentication in wireless networks, dubbed KRACK. An attacker exploiting the vulnerabilities could force the vulnerable system to reuse cryptographic session keys, enabling a range of cryptographic attacks against the ciphers used in WPA1 and WPA2. These vulnerabilities are only being fixed for certain Broadcom wifi chips, and might still be present in firmware for other wifi hardware.

For Debian 8 Jessie, these problems have been fixed in version 20161130-4~deb8u1. This version also adds new firmware and packages for use with Linux 4.9, and re-adds firmware-{adi,ralink} as transitional packages.

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