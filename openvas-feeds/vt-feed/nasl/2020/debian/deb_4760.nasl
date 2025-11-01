# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704760");
  script_cve_id("CVE-2020-12829", "CVE-2020-14364", "CVE-2020-15863", "CVE-2020-16092");
  script_tag(name:"creation_date", value:"2020-09-08 03:00:49 +0000 (Tue, 08 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 18:11:00 +0000 (Mon, 04 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-4760)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4760");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4760");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/qemu");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DSA-4760 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in QEMU, a fast processor emulator:

CVE-2020-12829

An integer overflow in the sm501 display device may result in denial of service.

CVE-2020-14364

An out-of-bounds write in the USB emulation code may result in guest-to-host code execution.

CVE-2020-15863

A buffer overflow in the XGMAC network device may result in denial of service or the execution of arbitrary code.

CVE-2020-16092

A triggerable assert in the e1000e and vmxnet3 devices may result in denial of service.

For the stable distribution (buster), these problems have been fixed in version 1:3.1+dfsg-8+deb10u8.

We recommend that you upgrade your qemu packages.

For the detailed security status of qemu please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);